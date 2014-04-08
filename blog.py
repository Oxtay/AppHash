import webapp2
import os
import validsign
import jinja2
import hmac
import hashlib
import random, string
import json
from google.appengine.ext import db

THANKS      = "Thank you! That's a valid response."
USER_ERR    = "That's not a valid username."
PASS_ERR    = "That wasn't a valid password."
VERIFY_ERR  = "Your passwords didn't match."
EMAIL_ERR   = "That's not a valid email."
SECRET      = "iamsosecret"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape = True)

###########################################
#                                         #
#               Basic functions           #
#                                         #
########################################### 

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)
    
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()
    
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))
    
def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val
        
class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
        
    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
        
    def render_json(self, d):
        json_str = json.dumps(d)
        self.response.headers.add_header('content-type', 'application/json', charset='utf-8')
        self.write(json_str)
        
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', 
            '%s=%s;Path=/' % (name, cookie_val))
            
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)
        
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
        
        if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'
        

###########################################
#                                         #
#               User Material             #
#                                         #
########################################### 

def make_salt(length = 5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, pw, h):
    salt = h.split(',')[0]
    h_valid = make_pw_hash(name, pw, salt)
    return h_valid == h
    
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()
    
    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return cls(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
    
###########################################
#                                         #
#               Blog Material             #
#                                         #
########################################### 

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)
        
    def as_dict(self):
        time_fmt = '%c'
        d = {'subject': self.subject,
            'content': self.content,
            'created': self.created.strftime(time_fmt),
            'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class BlogFront(BlogHandler):
    def get(self):
        posts = greetings = Post.all().order('-created')
        #posts = get_posts(self.request.remote_addr)
        if self.format == 'html':
            self.render('front.html', posts = posts)
        else:
            self.render_json([p.as_dict() for p in posts])

class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id))
        post = db.get(key)

        if not post:
            self.error(404)
            return
        if self.format == 'html':
            self.render("permalink.html", post = post)
        else:
            self.render_json(post.as_dict())

class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)
            
###########################################
#                                         #
#                    Signup               #
#                                         #
###########################################            

class Signup(BlogHandler):
    def get(self):
        self.render('signup.html')
        
    def post(self):
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify   = self.request.get("verify")
        self.email    = self.request.get("email")
        
        have_error = False
        params = dict(username = self.username, email = self.email)
                
        if not validsign.isValidUser(self.username):
            params['user_err'] = USER_ERR
            have_error = True
            
        if not validsign.isValidPass(self.password):
            params['pass_err'] = PASS_ERR
            have_error = True
        
        if not validsign.isValidEmail(self.email):
            params['email_err'] = EMAIL_ERR
            have_error = True
            
        if self.password != self.verify:
            params['verify_err'] = VERIFY_ERR
            have_error = True
            
        if have_error:
            self.render('signup.html', **params)
            
        else:          
            self.done()
            
    def done(self, *a, **kw):
        raise NotImplementedError
            
class Register(Signup):
    def done(self):
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists'
            self.render('signup.html', user_err = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            
            self.login(u)
            self.redirect('/blog')
            
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')
        
    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        
        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('/login-form.html', error = msg)
        
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/signup')
                        
class Welcome(BlogHandler):
    def get(self):        
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')
            
###########################################
#                                         #
#                    Main                 #
#                                         #
###########################################
          
class MainPage(BlogHandler):
    def get(self):
        self.response.write("Hello and Welcome!")
        self.redirect('/blog')
            

application = webapp2.WSGIApplication([
                        ('/', MainPage), 
                        ('/blog/?(?:\.json)?', BlogFront),
                        ('/blog/newpost', NewPost),
                        ('/blog/([0-9]+)(?:\.json)?', PostPage), 
                        ('/signup', Register),
                        ('/login', Login),
                        ('/logout', Logout), 
                        ('/welcome', Welcome)
                        ], 
                        debug=True)