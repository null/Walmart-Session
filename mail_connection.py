from email.header import decode_header
from email import message_from_bytes
from imaplib import IMAP4_SSL
from time import sleep
from re import search

import user_interface

class MailConnection:
    def __init__(self, server: str, port: int, username: str, password: str) -> None:
        self.emails: list = []
        self.otp: str = ""

        self.mail_server = IMAP4_SSL(server, port)
        self.connect_to_server(username, password)

    def decode_mime(self, string: str) -> str | None:
        if string is None:
            return None

        decoded_fragments: list = decode_header(string)
        fragments: list = []

        for fragment, encoding in decoded_fragments:
            if isinstance(fragment, bytes):
                if encoding:
                    fragments.append(fragment.decode(encoding))

                else:
                    fragments.append(fragment.decode("utf-8", errors="ignore"))

            else:
                fragments.append(fragment)

        return "".join(fragments)

    def connect_to_server(self, username: str, password: str) -> bool:
        try:
            self.mail_server.login(username, password)
            return True

        except:
            pass

        return False

    def move_to_trash(self, email_id: str, code: str) -> bool:
        try:
            self.mail_server.select("INBOX")

            result = self.mail_server.copy(str(email_id), "Trash")
            
            if result[0] == "OK":
                self.mail_server.store(str(email_id), "+FLAGS", "\\Deleted")
                self.mail_server.expunge()
                return True
                
        except:
            pass
        
        return False

    def fetch_otp(self, max_attempts: int = 7) -> str | None:
        for attempt in range(max_attempts):
            try:
                self.mail_server.select("INBOX")
                status, messages = self.mail_server.search(None, "UNDELETED")
                email_ids = messages[0].split()
                email_ids = email_ids[-5:]
                
                self.emails = []
                
                for email_id in reversed(email_ids):
                    status, data = self.mail_server.fetch(email_id, "(BODY[HEADER.FIELDS (SUBJECT FROM)])")
                    
                    if status == "OK":
                        msg = message_from_bytes(data[0][1])
                        
                        subject_data = msg.get("Subject", "")
                        subject = subject_data.strip()
                        subject = self.decode_mime(subject)
                        
                        from_data = msg.get("From", "")
                        from_email = self.decode_mime(from_data)
                        
                        email_match = search(r'<([^>]+)>|([^\s<>]+@[^\s<>]+)', from_email)
                        sender_email = email_match.group(1) or email_match.group(2) if email_match else from_email
                        
                        email_info = {
                            "id": email_id.decode(),
                            "subject": subject,
                            "sender_email": sender_email.strip()
                        }
                        self.emails.append(email_info)
                
                if self.emails:
                    for email_info in self.emails:
                        if email_info["sender_email"] == "help@walmart.com":
                            code_match = search(r'\b(\d{6})\b', email_info["subject"])
                            
                            if code_match:
                                code = code_match.group(1)
                                email_id = email_info["id"]
                                self.move_to_trash(email_id, code)
                                return code.strip()

                if attempt < max_attempts - 1:
                    sleep(5)
                    continue
                
                return None
                
            except:                
                if attempt < max_attempts - 1:
                    sleep(5)
                    continue

        return None
