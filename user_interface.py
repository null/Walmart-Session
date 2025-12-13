from os import system, name

class UI:
	def __init__(self,  email: str, logged_in: bool, website: str) -> None:
		self.logged_in: bool = logged_in
		self.website: str = website
		self.email: str = email
		self.login_str = None

		self.email_width = max(len(self.email), len("Email"))
		self.status_width = max(len("Logged In "), len("Logging In"), len("Status"))
		self.website_width = max(len(self.website), len("Website"))
		
		self.top_box_total_width = self.email_width + self.status_width + self.website_width + 16

		total_content_width = self.email_width + self.status_width + self.website_width + 5

		self.name: str = "null"
		min_name_width = max(len("Name"), 4)
		self.name_width = max(min_name_width, total_content_width // 3)

		self.shipping_address: str = "null"
		self.address_width = total_content_width - self.name_width

	def set_name(self, name: str) -> None:
		self.name: str = name

	def set_shipping_address(self, shipping_address: str) -> None:
		self.shipping_address: str = shipping_address

	def title(self) -> str:
		return "[ Walmart Product Monitor ]".center(len(self.top_row()))
	
	def top_row(self) -> str:
		return f"┌──{'─' * self.email_width}──┬──{'─' * self.status_width}──┬──{'─' * self.website_width}──┐"
	
	def title_row(self) -> str:
		return f"|  {'Email'.ljust(self.email_width)}  |  {'Status'.ljust(self.status_width)}  |  {'Website'.ljust(self.website_width)}  |"
	
	def middle_row(self) -> str:
		return f"├──{'─' * self.email_width}──┼──{'─' * self.status_width}──┼──{'─' * self.website_width}──┤"
	
	def details_row(self) -> str:
		return f"|  {self.email.ljust(self.email_width)}  |  {self.login_str.ljust(self.status_width)}  |  {self.website.ljust(self.website_width)}  |"
	
	def bottom_row(self) -> str:
		return f"└──{'─' * self.email_width}──┴──{'─' * self.status_width}──┴──{'─' * self.website_width}──┘"
	
	def top_info_row(self) -> str:
		return f"┌──{'─' * self.name_width}──┬──{'─' * self.address_width}──┐"
	
	def title_info_row(self) -> str:
		return f"|  {'Name'.ljust(self.name_width)}  |  {'Shipping Address'.ljust(self.address_width)}  |"
	
	def middle_info_row(self) -> str:
		return f"├──{'─' * self.name_width}──┼──{'─' * self.address_width}──┤"
	
	def info_row(self) -> str:
		return f"|  {self.name.ljust(self.name_width)}  |  {self.shipping_address.ljust(self.address_width)}  |"
	
	def bottom_info_row(self) -> str:
		return f"└──{'─' * self.name_width}──┴──{'─' * self.address_width}──┘"

	def log_separator(self) -> str:
		return f"{('├──' + '─' * (len(self.top_row()) + 10)) + '──┤'}"

	def log_display(self, logs) -> str:
		return f"\n\t\t   ".join(logs)

	def ui_str(self, logs, logged_in: bool = False) -> None:
		system("cls" if name == "nt" else "clear")

		self.login_str = "Logged In " if logged_in else "Logging In"

		print(f"""
			{self.title()}
			{self.top_row()}
			{self.title_row()}
			{self.middle_row()}
			{self.details_row()}
			{self.bottom_row()}
			{self.top_info_row()}
			{self.title_info_row()}
			{self.middle_info_row()}
			{self.info_row()}
			{self.bottom_info_row()}
		{self.log_separator()}
		   {self.log_display(logs)}
		""")