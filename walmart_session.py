from string import ascii_lowercase, ascii_letters, digits
from secrets import token_hex, token_bytes
from requests import Session, Response
from base64 import urlsafe_b64encode
from json import load, loads, dumps
from urllib.parse import quote
from hashlib import sha256
from random import choice
from re import search

import mail_connection

class WalmartSession:
    def __init__(self) -> None:
        with open("config.json") as cfg:
            config: dict = load(cfg)

        self.email: str = config["walmart_login_information"]["email"]
        self.server: str = config["mail_login_information"]["server"]
        self.port: int = config["mail_login_information"]["port"]
        self.username: str = config["mail_login_information"]["username"]
        self.password: str = config["mail_login_information"]["password"]
        self.code_challenge = None
        self.code_verifier = None

        self.session: Session = Session()
        self.session.headers.update({
            "Authority": "www.walmart.com",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Content-Type": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US,en;q=0.7",
            "Cache-Control": "max-age=0",
            "Priority": "u=0 i",
            "Referer": "https://www.walmart.com/",
            "Sec-Ch-Ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-User": "?1",
            "Sec-Gpc": "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        })

        self.correlation_id: str = self.generate_correlation_id()
        self.device_profile: str = self.generate_device_profile()
        self.traceparent: str = self.generate_traceparent()
        self.generate_pkce_pair()

        self.base_headers: dict = {
            "Accept": "application/json",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "en-US",
            "Content-Type": "application/json",
            "Content-Length": "1121",
            "Device_profile_ref_id": self.device_profile,
            "Origin": "https://identity.walmart.com",
            "Priority": "u=1, i",
            "Referer": None,
            "Sec-Ch-Ua": '"Chromium";v="142", "Brave";v="142", "Not_A Brand";v="99"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Gpc": "1",
            "Tenant-Id": None,
            "Traceparent": self.traceparent,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36",
            "Wm_mp": "true",
            "Wm_page_url": None,
            "Wm_qos.Correlation_Id": self.correlation_id,
            "X-Apollo-Operation-Name": None,
            "X-Enable-Server-Timing": "1",
            "X-Latency-Trace": "1",
            "X-O-Bu": "WALMART-US",
            "X-O-Ccm": "server",
            "X-O-Correlation-Id": self.correlation_id,
            "X-O-Gql-Query": None,
            "X-O-Mart": "B2C",
            "X-O-Platform": "rweb",
            "X-O-Platform-Version": "usweb-1.231.5-a034267af522518f902d66840b28d33cf95a4099-N81117r",
            "X-O-Segment": "oaoh"
        }

        self.base_payload: dict = {
            "query": None,
            "variables": {
                "input": {
                    "loginId": self.email,
                    "loginIdType": "EMAIL",
                    "ssoOptions": {
                        "wasConsentCaptured": True,
                        "callbackUrl": None,
                        "clientId": None,
                        "scope": None,
                        "state": "/?action=SignIn&rm=true",
                        "challenge": self.code_challenge
                    }
                }
            }
        }

        self.redirect_uri = None
        self.client_id = None
        self.tenant_id = None
        self.scope = None

        self.isomorphic_session_id = None
        self.render_view_id = None
        self.trace_id = None

        self.auth_code = None
        self.walmart_session: Session = self.login()
        
    @staticmethod
    def generate_device_profile(length: int = 40) -> str:
        return "".join(choice(ascii_lowercase + digits) for _ in range(length)) + "-"
    
    @staticmethod
    def generate_correlation_id(length: int = 32) -> str:
        return "".join(choice(ascii_letters + digits + "_-") for _ in range(length))
    
    @staticmethod
    def generate_traceparent() -> str:
        return f"00-{token_hex(16)}-{token_hex(8)}-00"
    
    def generate_pkce_pair(self) -> None:
        self.code_verifier = urlsafe_b64encode(token_bytes(32)).decode("utf-8").rstrip("=")
        self.code_challenge = urlsafe_b64encode(sha256(self.code_verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")
    
    def extract_oauth_params(self, html_content) -> bool:
        match = search(r'"oidcParams"\s*:\s*({[^}]+})', html_content)
        
        if match:
            try:
                oidc_params = loads(match.group(1))
                self.client_id: str = oidc_params.get("clientId")
                self.scope: str = oidc_params.get("scope")
                self.tenant_id: str = oidc_params.get("tenantId")
                redirect_uri: str = oidc_params.get("redirectUri")

                self.base_headers["tenant-id"] = self.tenant_id

                if redirect_uri.startswith("/"):
                    self.redirect_uri: str = f"https://www.walmart.com{redirect_uri}"
                    self.base_payload["variables"]["input"]["ssoOptions"]["callbackUrl"] = self.redirect_uri
                    self.base_payload["variables"]["input"]["ssoOptions"]["clientId"] = self.client_id
                    self.base_payload["variables"]["input"]["ssoOptions"]["scope"] = self.scope
                    return True

                raise Exception()

            except:
                pass
        
        return False

    def extract_autenticated_oauth_params(self, html_content) -> bool:
        try:
            isomorphic_match = search(r'"isomorphicSessionId"\s*:\s*"([a-zA-Z0-9_-]+)"', html_content)
            if isomorphic_match:
                self.isomorphic_session_id = isomorphic_match.group(1)

            else:
                raise Exception()

            render_match = search(r'"renderViewId"\s*:\s*"([a-f0-9-]{36})"', html_content)
            if render_match:
                self.render_view_id = render_match.group(1)

            else:
                raise Exception()

            trace_id_match = search(r'"traceId"\s*:\s*"([a-f0-9]{32})"', html_content)
            if trace_id_match:
                self.trace_id = trace_id_match.group(1)
                return True

            raise Exception()

        except:
            pass

        return False

    def get_home_webpage(self) -> bool:
        try:
            response: Response = self.session.get(
                "https://www.walmart.com/"
            )

            if response.status_code == 200:
                if not self.extract_oauth_params(response.text):
                    exit()
                    
                return True

            raise Exception()

        except:
            pass

        return False
        
    def get_login_page(self) -> bool: 
        try:
            headers = self.base_headers.copy()
            headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
            headers["Accept-Language"] = "en-US,en;q=0.9"
            headers["Priority"] = "u=0, i"
            headers["Referer"] = "https://www.walmart.com/"
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "same-site"
            headers["Sec-Fetch-User"] = "?1"
            headers["Upgrade-Insecure-Requests"] = "1"

            params: dict = {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
                "tenant_id": self.tenant_id,
                "state": "/",
                "code_challenge": self.code_challenge
            }

            response: Response = self.session.get(
                "https://identity.walmart.com/account/login",
                headers=headers,
                params=params
            )

            if response.status_code == 200:
                return True

            raise Exception()

        except:
            pass

        return False

    def generate_otp(self) -> bool:
        try:
            headers = self.base_headers.copy()
            headers["Referer"] = f"https://identity.walmart.com/account/signin/withotpchoice?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            headers["Wm_page_url"] = f"https://identity.walmart.com/account/signin/withotpchoice?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            headers["X-Apollo-Operation-Name"] = "GenerateOtp"
            headers["X-O-Gql-Query"] = "mutation GenerateOtp"

            self.base_payload["query"] = "mutation GenerateOtp($input:GenerateOTPInput!){generateOTP(input:$input){errors{...GenerateOtpErrorFragment}otpResult{...GenerateOtpResultFragment}}}fragment GenerateOtpErrorFragment on IdentityGenerateOTPError{code message}fragment GenerateOtpResultFragment on GenerateOTPResult{receiptId otpOperation otpType otherAccountsWithPhone action{alternateOption currentOption}}"
            self.base_payload["variables"]["input"]["otpOperation"] = "OTP_EMAIL_SIGN_IN"

            response: Response = self.session.post(
                "https://identity.walmart.com/orchestra/idp/graphql",
                headers=headers,
                json=self.base_payload
            )

            if response.status_code == 200:
                return True

            raise Exception()

        except:
            pass

        return False

    def submit_otp(self, otp_code: str) -> bool:
        try:
            headers = self.base_headers.copy()
            headers["Referer"] = f"https://identity.walmart.com/account/signin/otponly?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            headers["Wm_page_url"] = f"https://identity.walmart.com/account/signin/otponly?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            headers["X-Apollo-Operation-Name"] = "SignInWithOTP"
            headers["X-O-Gql-Query"] = "mutation SignInWithOTP"

            self.base_payload["query"] = "mutation SignInWithOTP( $input:SignInWithOTPInput! $includePhoneInfo:Boolean = false ){signInWithOTP(input:$input){auth{...SignInOtpAuthFragment}authCode{authCode cid}phoneInfo @include(if:$includePhoneInfo){...SignInOtpPhoneInfoFragment}multiFactorInfo{ignoreFactor}errors{...SignInOtpErrorFragment}}}fragment SignInOtpAuthFragment on AuthResult{loginId cid authCode identityToken}fragment SignInOtpPhoneInfoFragment on PhoneInfo{phoneLastFour shouldCollectPhone isEmailSessionTrusted loginId isPhoneSessionTrusted isFirstSession isEmailValidated}fragment SignInOtpErrorFragment on IdentitySignInWithOTPError{code message}"
            self.base_payload["variables"]["input"]["otpCode"] = otp_code
            self.base_payload["variables"]["input"]["rememberMe"] = True
            self.base_payload["variables"]["includePhoneInfo"] = True


            response: Response = self.session.post(
                "https://identity.walmart.com/orchestra/idp/graphql",
                headers=headers,
                json=self.base_payload
            )
            
            if response.status_code == 200:
                self.auth_code: str = response.json()["data"]["signInWithOTP"]["authCode"]["authCode"]
                return True

            raise Exception()

        except:
            pass

        return False
    
    def verify_token(self) -> bool:
        try:
            self.session.cookies.set(
                "walmart-identity-web-code-verifier",
                self.code_verifier,
                domain=".walmart.com",
                path="/"
            )
            
            params: dict = {
                "state": "/",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
                "code": self.auth_code,
                "action": "SignIn",
                "rm": "true"
            }
            
            headers = {
                "Referer": "https://identity.walmart.com/",
                "Sec-Fetch-Site": "same-site",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Dest": "document"
            }
            
            response: Response = self.session.get(
                "https://www.walmart.com/account/verifyToken",
                headers=headers,
                params=params
            )

            if response.status_code == 200:
                return True

            raise Exception()
                
        except:
            pass

        return False

    def get_account_webpage(self) -> bool:
        try:
            response = self.session.get("https://www.walmart.com/account")

            if response.status_code == 200:
                if self.extract_autenticated_oauth_params(response.text):
                    return True

            raise Exception()

        except:
            pass

        return False

    def display_name(self) -> bool:
        try:
            variables = quote(dumps({
                "isCashiLinked": False,
                "enableCountryCallingCode": False,
                "enablePhoneCollection": False,
                "enableMembershipId": False,
                "enableMembershipAutoRenew": False,
                "enableMembershipQuery": True,
                "enableWcp": False,
                "enableMembershipAutoRenewalModal": False,
                "includeResidencyRegionInfo": False,
                "sessionInput": {},
                "includeSessionInfo": False
            }))

            headers = self.base_headers.copy()
            headers["Baggage"] = f"trafficType=customer,deviceType=desktop,renderScope=CSR,webRequestSource=Browser,pageName=account,isomorphicSessionId={self.isomorphic_session_id},renderViewId={self.render_view_id}"
            headers["Referer"] = "https://www.walmart.com/account"
            headers["Wm_page_url"] = "https://www.walmart.com/account"
            headers["Wm-Client-Traceid"] = token_hex(16)
            headers["X-Apollo-Operation-Name"] = "accountLandingPage"
            headers["X-O-Gql-Query"] = "query accountLandingPage"

            response: Response = self.session.get(
                f"https://www.walmart.com/orchestra/home/graphql/accountLandingPage/781bca8419fd5b5e7a88ff6690e3ce97007469afd2c59b79b44d599218eb4d4d?variables={variables}",
                headers=headers
            )

            if response.status_code == 200:
                print(f"Logged In As: {response.json()["data"]["account"]["profile"]["firstName"]}")
                return True

            raise Exception()

        except:
            pass

        return False

    def login(self) -> Session:
        self.get_home_webpage()
        self.get_login_page()
        self.generate_otp()

        items: str = mail_connection.MailConnection(self.server, self.port, self.username, self.password).fetch_otp()
        self.logs = items[1]
        self.submit_otp(items[0])
        self.verify_token()
        self.get_account_webpage()
        self.display_name()

        return self.session


auth = WalmartSession()
