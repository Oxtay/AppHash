import re

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def isValidUser(username):
    return USER_RE.match(username)
    
def isValidPass(password):
    return PASSWORD_RE.match(password)

def isValidEmail(email):
    return not email or EMAIL_RE.match(email)
    
# print isValidUser("Okh tay") -> None
# print isValidPass("pa ss") -> <_sre.SRE_Match object at ...>
# print isValidEmail("okh@yahoocom") -> None