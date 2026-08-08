from string import ascii_lowercase, ascii_letters, digits
from secrets import token_hex, token_bytes
from requests import Session, Response
from base64 import urlsafe_b64encode
from json import load, loads
from re import search, Match
from hashlib import sha256
from random import choice
from time import time
from os import path

from mail_connection import MailConnection

class WalmartAccountSession:
    def __init__(self) -> None:
        with open(path.join(path.dirname(path.realpath(__file__)), "config.json")) as cfg:
            self.config: dict = load(cfg)

        with open(path.join(path.dirname(path.realpath(__file__)), "header_config.json")) as cfg:
            self.header_config: dict = load(cfg)

        with open(path.join(path.dirname(path.realpath(__file__)), "params_config.json")) as cfg:
            self.params_config: dict = load(cfg)

        with open(path.join(path.dirname(path.realpath(__file__)), "payload_config.json")) as cfg:
            self.payload_config: dict = load(cfg)

        self.session: Session = Session()

        self.code_challenge = None
        self.code_verifier = None
        self.generate_pkce_pair()

        self.payload_config["otp_payload"]["variables"]["input"]["loginId"] = self.config["walmart_login_information"]["email"]
        self.payload_config["otp_payload"]["variables"]["input"]["ssoOptions"]["challenge"] = self.code_challenge

        self.correlation_id: str = self.generate_correlation_id()
        self.device_profile: str = self.generate_device_profile()
        self.traceparent: str = self.generate_traceparent()

        self.redirect_uri = None
        self.client_id = None
        self.tenant_id = None
        self.scope = None

        self.isomorphic_session_id = None
        self.render_view_id = None
        self.trace_id = None

        self.auth_code = None

        self.cart_id: str = "55035e55-ceb1-4623-9c98-7fa3d04d4499"
        self.phone_number = None
        self.contract_id = None
        self.longitude = None
        self.latitude = None
        self.offer_id = None
        
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
        self.code_verifier: str = urlsafe_b64encode(token_bytes(32)).decode("utf-8").rstrip("=")
        self.code_challenge: str = urlsafe_b64encode(sha256(self.code_verifier.encode("utf-8")).digest()).decode("utf-8").rstrip("=")
    
    def extract_oauth_params(self, html_content: str) -> bool:
        match: Match = search(r'"oidcParams"\s*:\s*({[^}]+})', html_content)
        
        if match:
            try:
                oidc_params = loads(match.group(1))
                self.client_id: str = oidc_params.get("clientId")
                self.scope: str = oidc_params.get("scope")
                self.tenant_id: str = oidc_params.get("tenantId")
                redirect_uri: str = oidc_params.get("redirectUri")

                if redirect_uri.startswith("/"):
                    self.redirect_uri: str = f"https://www.walmart.com{redirect_uri}"
                    self.payload_config["otp_payload"]["variables"]["input"]["ssoOptions"]["callbackUrl"] = self.redirect_uri
                    self.payload_config["otp_payload"]["variables"]["input"]["ssoOptions"]["clientId"] = self.client_id
                    self.payload_config["otp_payload"]["variables"]["input"]["ssoOptions"]["scope"] = self.scope
                    return True

            except:
                pass

        return False

    def extract_authenticated_oauth_params(self, html_content: str) -> bool:
        try:
            isomorphic_match: Match = search(r'"isomorphicSessionId"\s*:\s*"([a-zA-Z0-9_-]+)"', html_content)
            if isomorphic_match:
                self.isomorphic_session_id: str = isomorphic_match.group(1)

            else:
                return False

            render_match: Match = search(r'"renderViewId"\s*:\s*"([a-f0-9-]{36})"', html_content)
            if render_match:
                self.render_view_id: str = render_match.group(1)

            else:
                return False

            trace_id_match: Match = search(r'"traceId"\s*:\s*"([a-f0-9]{32})"', html_content)
            if trace_id_match:
                self.trace_id: str = trace_id_match.group(1)
                return True

        except:
            pass

        return False

    def get_home_webpage(self) -> None:
        try:
            response: Response = self.session.get(
                "https://www.walmart.com/",
                headers=self.header_config["get_home_webpage"]
            )
            
            if response.status_code == 200:
                self.extract_oauth_params(response.text)
                self.get_login_page()

        except:
            pass
        
    def get_login_page(self) -> None: 
        try:
            self.params_config["get_login_page"]["client_id"] = self.client_id
            self.params_config["get_login_page"]["redirect_uri"] = self.redirect_uri
            self.params_config["get_login_page"]["scope"] = self.scope
            self.params_config["get_login_page"]["tenant_id"] = self.tenant_id
            self.params_config["get_login_page"]["code_challenge"] = self.code_challenge

            response: Response = self.session.get(
                "https://identity.walmart.com/account/login",
                headers=self.header_config["get_login_page"],
                params=self.params_config["get_login_page"]
            )

            if response.status_code == 200:
            	self.generate_otp()

        except:
            pass

    def generate_otp(self) -> None:
        try:
            self.header_config["generate_otp"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["generate_otp"]["Referer"] = f"https://identity.walmart.com/account/signin/withotpchoice?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            self.header_config["generate_otp"]["Tenant-Id"] = self.tenant_id
            self.header_config["generate_otp"]["Traceparent"] = self.traceparent
            self.header_config["generate_otp"]["Wm_page_url"] = f"https://identity.walmart.com/account/signin/withotpchoice?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            self.header_config["generate_otp"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["generate_otp"]["X-O-Correlation-Id"] = self.correlation_id

            self.payload_config["otp_payload"]["query"] = "mutation GenerateOtp($input:GenerateOTPInput!){generateOTP(input:$input){errors{...GenerateOtpErrorFragment}otpResult{...GenerateOtpResultFragment}}}fragment GenerateOtpErrorFragment on IdentityGenerateOTPError{code message}fragment GenerateOtpResultFragment on GenerateOTPResult{receiptId otpOperation otpType otherAccountsWithPhone action{alternateOption currentOption}}"
            self.payload_config["otp_payload"]["variables"]["input"]["otpOperation"] = "OTP_EMAIL_SIGN_IN"

            response: Response = self.session.post(
                "https://identity.walmart.com/orchestra/idp/graphql",
                headers=self.header_config["generate_otp"],
                json=self.payload_config["otp_payload"]
            )

            if response.status_code == 200:
            	self.submit_otp(MailConnection(self.config["mail_login_information"]["server"], self.config["mail_login_information"]["port"], self.config["mail_login_information"]["username"], self.config["mail_login_information"]["password"]).fetch_otp())

        except:
            pass

    def submit_otp(self, otp_code: str) -> None:
        try:            
            self.header_config["submit_otp"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["submit_otp"]["Referer"] = f"https://identity.walmart.com/account/signin/otponly?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            self.header_config["submit_otp"]["Tenant-Id"] = self.tenant_id
            self.header_config["submit_otp"]["Traceparent"] = self.traceparent
            self.header_config["submit_otp"]["Wm_page_url"] = f"https://identity.walmart.com/account/signin/otponly?scope={self.scope.replace(' ', '%20')}&redirect_uri={self.redirect_uri}&client_id={self.client_id}&tenant_id={self.tenant_id}&code_challenge={self.code_challenge}&state=%2F%3Faction%3DSignIn%26rm%3Dtrue"
            self.header_config["submit_otp"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["submit_otp"]["X-O-Correlation-Id"] = self.correlation_id

            self.payload_config["otp_payload"]["query"] = "mutation SignInWithOTP( $input:SignInWithOTPInput! $includePhoneInfo:Boolean = false ){signInWithOTP(input:$input){auth{...SignInOtpAuthFragment}authCode{authCode cid}phoneInfo @include(if:$includePhoneInfo){...SignInOtpPhoneInfoFragment}multiFactorInfo{ignoreFactor}errors{...SignInOtpErrorFragment}}}fragment SignInOtpAuthFragment on AuthResult{loginId cid authCode identityToken}fragment SignInOtpPhoneInfoFragment on PhoneInfo{phoneLastFour shouldCollectPhone isEmailSessionTrusted loginId isPhoneSessionTrusted isFirstSession isEmailValidated}fragment SignInOtpErrorFragment on IdentitySignInWithOTPError{code message}"
            self.payload_config["otp_payload"]["variables"]["input"]["otpCode"] = otp_code
            self.payload_config["otp_payload"]["variables"]["input"]["rememberMe"] = True
            self.payload_config["otp_payload"]["variables"]["includePhoneInfo"] = True

            response: Response = self.session.post(
                "https://identity.walmart.com/orchestra/idp/graphql",
                headers=self.header_config["submit_otp"],
                json=self.payload_config["otp_payload"]
            )

            if response.status_code == 200:
                self.auth_code = response.json()["data"]["signInWithOTP"]["authCode"]["authCode"]
                self.verify_token()

        except:
            pass
    
    def verify_token(self) -> None:
        try:
            self.session.cookies.set(
                "walmart-identity-web-code-verifier",
                self.code_verifier,
                domain=".walmart.com",
                path="/"
            )

            self.params_config["verify_token"]["client_id"] = self.client_id
            self.params_config["verify_token"]["redirect_uri"] = self.redirect_uri
            self.params_config["verify_token"]["scope"] = self.scope
            self.params_config["verify_token"]["code"] = self.auth_code

            response: Response = self.session.get(
                "https://www.walmart.com/account/verifyToken",
                headers=self.header_config["verify_token"],
                params=self.params_config["verify_token"]
            )

            if response.status_code == 200:
                self.get_account_webpage()
                
        except:
            pass

    def get_account_webpage(self) -> None:
        try:
            response: Response = self.session.get(
                "https://www.walmart.com/account",
                headers=self.header_config["get_account_webpage"]
            )

            if response.status_code == 200:
                self.extract_authenticated_oauth_params(response.text)
                self.display_name()

        except:
            pass

    def display_name(self) -> None:
        try:
            self.header_config["display_name"]["Baggage"] = f"trafficType=customer,deviceType=desktop,renderScope=CSR,webRequestSource=Browser,pageName=account,isomorphicSessionId={self.isomorphic_session_id},renderViewId={self.render_view_id}"
            self.header_config["display_name"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["display_name"]["Tenant-Id"] = self.tenant_id
            self.header_config["display_name"]["Traceparent"] = self.traceparent
            self.header_config["display_name"]["Wm-Client-TraceId"] = token_hex(16)
            self.header_config["display_name"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["display_name"]["X-O-Correlation-Id"] = self.correlation_id

            response: Response = self.session.get(
                f"https://www.walmart.com/orchestra/home/graphql/accountLandingPage/781bca8419fd5b5e7a88ff6690e3ce97007469afd2c59b79b44d599218eb4d4d",
                headers=self.header_config["display_name"],
                params=self.params_config["display_name"]
            )

            if response.status_code == 200:
                print(f"Logged In As: {response.json()['data']['account']['profile']['emailAddress']}")
                self.phone_number: str = response.json()["data"]["account"]["profile"]["phoneNumber"]

        except:
            pass

    def get_product_page(self, item_id: str, product_name: str) -> None:
        try:
            response: Response = self.session.get(
                f"https://www.walmart.com/ip/{product_name}/{item_id}?classType=REGULAR&athbdg=L1600&from=/search",
                headers=self.header_config["get_product_page"]
            )

            if response.status_code == 200:
                self.offer_id: Match = search(r'"selectedOfferId"\s*:\s*"([^"]+)"', response.text).group(1)
                self.price: Match = search(r'"priceString"\s*:\s*"([^"]+)"', response.text).group(1).lstrip("$")
                self.post_to_cart(item_id, product_name)

        except:
            pass

    def post_to_cart(self, item_id: str, product_name: str) -> None:
        try:
            self.header_config["post_to_cart"]["Referer"] = f"https://www.walmart.com/ip/{product_name}/{item_id}?classType=REGULAR&athbdg=L1600&from=/search"
            self.header_config["post_to_cart"]["Baggage"] = f"trafficType=customer,deviceType=desktop,renderScope=SSR,webRequestSource=Browser,pageName=itemPage,requestTs={int(time() * 1000)}"
            self.header_config["post_to_cart"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["post_to_cart"]["Tenant-Id"] = self.tenant_id
            self.header_config["post_to_cart"]["Traceparent"] = f"00-{self.trace_id}-{self.trace_id[:16]}-00"
            self.header_config["post_to_cart"]["Wm-Client-Traceid"] = self.trace_id
            self.header_config["post_to_cart"]["Wm_page_url"] = f"https://www.walmart.com/ip/{product_name}/{item_id}?classType=REGULAR&athbdg=L1600&from=/search"
            self.header_config["post_to_cart"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["post_to_cart"]["X-O-Correlation-Id"] = self.correlation_id

            self.payload_config["post_to_cart"]["variables"]["input"]["cartId"] = self.cart_id
            self.payload_config["post_to_cart"]["variables"]["input"]["items"][0]["offerId"] = self.offer_id
            self.payload_config["post_to_cart"]["variables"]["input"]["items"][0]["usItemId"] = item_id
            self.payload_config["post_to_cart"]["variables"]["input"]["items"][0]["name"] = product_name
            
            response: Response = self.session.post(
                f"https://www.walmart.com/orchestra/home/graphql/updateItems/d0551c7ae624ce70f680bf4984185ca965b3a8faace9d78b890072f3f1a6dcf5",
                headers=self.header_config["post_to_cart"],
                json=self.payload_config["post_to_cart"]
            )

            if response.status_code == 200:
            	self.create_contract()

        except:
            pass
  
    def create_contract(self) -> None:
        try:
            self.header_config["create_contract"]["Referer"] = f"https://www.walmart.com/checkout/review-order?cartId={self.cart_id}"
            self.header_config["create_contract"]["Baggage"] = f"trafficType=customer,deviceType=desktop,renderScope=SSR,webRequestSource=Browser,pageName=checkout,isomorphicSessionId={self.isomorphic_session_id},renderViewId={self.render_view_id},requestTs={int(time() * 1000)},tpid=00-{self.trace_id}-{self.trace_id[:16]}-00"
            self.header_config["create_contract"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["create_contract"]["Tenant-Id"] = self.tenant_id
            self.header_config["create_contract"]["Traceparent"] = f"00-{self.trace_id}-{self.trace_id[:16]}-00"
            self.header_config["create_contract"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["create_contract"]["X-O-Correlation-Id"] = self.correlation_id

            self.payload_config["create_contract"]["variables"]["createContractInput"]["cartId"] = self.cart_id

            response: Response = self.session.post(
                "https://www.walmart.com/orchestra/cartxo/graphql/CreateContract/8aede535e8f932644eddf0e95b73de5d96897e38312ca0e7e1d37fd79f5d6cb2",
                headers=self.header_config["create_contract"],
                json=self.payload_config["create_contract"]
            )
            
            if response.status_code == 200:
                self.longitude: float = response.json()["data"]["createPurchaseContract"]["fulfillment"]["deliveryAddress"]["longitude"]
                self.latitude: float = response.json()["data"]["createPurchaseContract"]["fulfillment"]["deliveryAddress"]["latitude"]
                self.contract_id: str = response.json()["data"]["createPurchaseContract"]["id"]
                self.place_order()

        except:
            pass

    def place_order(self) -> None:
        try:
            self.header_config["place_order"]["Referer"] = f"https://www.walmart.com/checkout/review-order?cartId={self.cart_id}"
            self.header_config["place_order"]["Baggage"] = f"trafficType=customer,deviceType=desktop,renderScope=SSR,webRequestSource=Browser,pageName=checkout,isomorphicSessionId={self.isomorphic_session_id},renderViewId={self.render_view_id},requestTs={int(time() * 1000)},tpid=00-{self.trace_id}-{self.trace_id[:16]}-00"
            self.header_config["place_order"]["Device_profile_ref_id"] = self.device_profile
            self.header_config["place_order"]["Tenant-Id"] = self.tenant_id
            self.header_config["place_order"]["Traceparent"] = f"00-{self.trace_id}-{self.trace_id[:16]}-00"
            self.header_config["place_order"]["Wm_qos.Correlation_id"] = self.correlation_id
            self.header_config["place_order"]["X-O-Correlation-Id"] = self.correlation_id

            self.payload_config["place_order"]["variables"]["placeOrderInput"]["contractId"] = self.contract_id
            self.payload_config["place_order"]["variables"]["placeOrderInput"]["deliveryInstructionDetails"][0]["pinDropDetails"]["pinLat"] = self.latitude
            self.payload_config["place_order"]["variables"]["placeOrderInput"]["deliveryInstructionDetails"][0]["pinDropDetails"]["pinLong"] = self.longitude
            self.payload_config["place_order"]["variables"]["placeOrderInput"]["mobileNumber"] = self.phone_number
            self.payload_config["place_order"]["variables"]["placeOrderInput"]["emailAddress"] = self.config["walmart_login_information"]["email"]

            response: Response = self.session.post(
                "https://www.walmart.com/orchestra/cartxo/graphql/PlaceOrder/b8b117bb90a5ae08ce88a0572eba5cdde383cdaec24f52b50940ed3287c4957a",
                headers=self.header_config["place_order"],
                json=self.payload_config["place_order"]
            )
            
            if response.status_code == 200:
                print(f"Placed order: {response.json()['data']['placeOrder']['order']['id']}")

        except:
            pass

auth = WalmartAccountSession()
auth.get_home_webpage()
auth.get_product_page("885116895", "Great-Value-Everyday-Disposable-Paper-Plates-8-5-100-Count") # product example being passed in as params