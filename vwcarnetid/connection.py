import base64
import aiohttp
import asyncio
import uuid
import hashlib
from base64 import b64encode
import time
import os
from urllib.parse import parse_qs, urljoin, urlparse
from aiohttp.client import ClientSession
from aiohttp.client_reqrep import ClientResponse
from bs4 import BeautifulSoup
from bs4.element import Tag
import logging

_LOGGER = logging.getLogger(__name__)


def base64URLEncode(s):
    return base64.urlsafe_b64encode(s).rstrip(b'=')


def getNonce():
    ts = "%d" % (time.time())
    sha256 = hashlib.sha256()
    sha256.update(ts.encode())
    return b64encode(sha256.digest()).decode('utf-8')[:-1]


def getCodeVerifier() -> bytes:
    return base64URLEncode(os.urandom(32))


def getPKCE(codeVerifier) -> str:
    return base64URLEncode(hashlib.sha256(codeVerifier).digest()).decode()


def checkStatus(req: ClientResponse):
    if req.status != 200:
        raise Exception("Request failed")


def getFormData(form: Tag):
    return dict([
        (t['name'], t['value']) for t in form.find_all('input', type='hidden')
    ])


def getFormAction(form: Tag) -> str:
    return form.get('action')


async def requestToSoup(request: ClientResponse) -> BeautifulSoup:
    content = await request.text()
    return BeautifulSoup(content, BS_PARSER)


def extractTokens(url: str) -> tuple[str]:
    query = parse_qs(urlparse(url).fragment)
    authCode = query.get('code')[0]
    idToken = query.get('id_token')[0]

    return (authCode, idToken)


BRAND = 'VW'

APP_URI = 'carnet://identity-kit/login'
OPENID_CONFIG = "https://identity.vwgroup.io/.well-known/openid-configuration"
REFRESH_TOKEN = 'https://tokenrefreshservice.apps.emea.vwapps.io/exchangeAuthCode'

AUTH_HEADERS = {
    'Connection': 'keep-alive',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate',
    'Content-Type': 'application/x-www-form-urlencoded',
    'x-requested-with': 'We Connect',
    'User-Agent': 'okhttp/3.14.7',
    'X-App-Name': 'We Connect'
}

BS_PARSER = "html.parser"


class Connection:
    def __init__(self, session: ClientSession) -> None:
        self._authHeaders = AUTH_HEADERS
        self._tokens = {}
        self._session = session

    async def login(self, email: str, password: str) -> bool:
        codeVerifier = getCodeVerifier()
        config = await self._getOpenIdConfig()

        authEndpoint = config['authorization_endpoint']
        authIssuer = config['issuer']

        loginPageUrl = await self._getLoginPageUrl(authEndpoint, codeVerifier)

        targetUrl = await self._fillInLoginForm(loginPageUrl, email, password, authIssuer, authEndpoint)

        authCode, idToken = await self._followRedirectsToToken(targetUrl)

        self._tokens['client'] = await self._getNewTokens(authCode, idToken, codeVerifier)

    async def _getOpenIdConfig(self):
        request = await self._session.get(OPENID_CONFIG)
        data = await request.json()
        return data

    async def _getLoginPageUrl(self, endPoint: str, codeVerifier: bytes) -> str:
        stateUUID = getNonce()
        nonceUUID = getNonce()
        challenge = getPKCE(codeVerifier)
        request = await self._session.get(f"{endPoint}?redirect_uri={APP_URI}&prompt=login&nonce={nonceUUID}&state={stateUUID}&code_challenge_method=s256&code_challenge={challenge}&response_type=code id_token token&client_id=9496332b-ea03-4091-a224-8c746b885068%40apps_vw-dilab_com&scope=openid mbb profile cars address email birthdate nickname phone", allow_redirects=False, headers=self._authHeaders)

        if request.headers.get('Location', False):
            url = urljoin(endPoint, request.headers.get('Location'))

            if 'error' in url:
                raise Exception(f"Unable to login. {url}")
        else:
            raise Exception("Missing 'Location' header")

        return url

    async def _fillInLoginForm(self, loginPageUrl: str, email: str, password: str, issuer: str, endpoint: str):
        self._authHeaders['Origin'] = issuer
        self._authHeaders['Referer'] = endpoint

        # get login page
        request = await self._session.get(url=loginPageUrl, headers=self._authHeaders, allow_redirects=False)

        checkStatus(request)

        responseSoup = await requestToSoup(request)

        # fill in and submit email form
        emailForm = responseSoup.find('form', id='emailPasswordForm')

        emailFormData = getFormData(emailForm)
        emailFormData['email'] = email

        emailFormPostUrl = issuer + getFormAction(emailForm)

        # post and get password form
        request = await self._session.post(url=emailFormPostUrl, headers=self._authHeaders, data=emailFormData)
        checkStatus(request)

        responseSoup = await requestToSoup(request)

        # fill in and submit password form
        passwordForm = responseSoup.find('form', id='credentialsForm')

        passwordFormData = getFormData(passwordForm)
        passwordFormData['password'] = password
        passwordFormPostUrl = issuer + getFormAction(passwordForm)

        # post password form data
        self._authHeaders['Referer'] = emailFormPostUrl
        request = await self._session.post(url=passwordFormPostUrl, headers=self._authHeaders, data=passwordFormData, allow_redirects=False)

        return urljoin(passwordFormPostUrl, request.headers["Location"])

    async def _followRedirectsToToken(self, startUrl: str, maxRedirects=10) -> tuple[str]:
        redirect = startUrl

        while not redirect.startswith(APP_URI):
            request = await self._session.get(url=redirect, headers=self._authHeaders, allow_redirects=False)

            if not request.headers.get('Location', False):
                _LOGGER.warning(
                    "Does this user have any car with connect services?")
                raise Exception("User is unauthorized")

            redirect = urljoin(redirect, request.headers['Location'])

            maxRedirects -= 1
            if maxRedirects == 0:
                _LOGGER.warning('To0 many redirect before getting a token')
                raise Exception('Too many redirects')

        return extractTokens(redirect)

    async def _getNewTokens(self, auth: str, id: str, verifier: str):
        exchangeTokenBody = {
            'auth_code': auth,
            'id_token': id,
            'code_verfier': verifier,
            'brand': BRAND
        }

        request = await self._session.post(url=REFRESH_TOKEN, headers=self._authHeaders, data=exchangeTokenBody, allow_redirects=False)

        checkStatus(request)

        tokens = await request.json()

        if 'error' in tokens:
            error = tokens.get('error', '')

            raise Exception(error)

        return tokens


async def main():
    async with ClientSession(headers={'Connection': 'keep-alive'}) as session:
        connection = Connection(session)

        await session.close()

if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    # loop.run(main())
    loop.run_until_complete(main())
