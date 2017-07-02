import os
from string import letters
import webapp2
import re
import cgi
import jinja2
import random
import hashlib
import hmac

from google.appengine.ext import db 

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = \
    jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                       autoescape=True)

secret = 'finger'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' %(val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    #print("the secure val is: %s" % secure_val)
    if secure_val == make_secure_val(val):
        return val


class BaseHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))

    def set_secure_cookie(self, name,val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie','%s=%s; Path=/' % (name,cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        print("thr uid is %s " % uid)
        self.user = uid and User.by_id(int(uid))
        print("this is user.by %s" % User.by_id(int(uid)))

def render_post(response, post):
    response.out.write('<b' + post.subject + '</b><br>')
    response.out.write(post.content) 

class MainPage(BaseHandler):
    def get(self):
        self.write("Hi, welcome to this blog")

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    print("the value of h is: %s" % h)
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users',group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())
    
    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name=', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash= make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        print("part 2 login")
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u
### blog stuff

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

class BlogFront(BaseHandler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc limit 10")
        self.render('front.html', posts = posts)

class PostPage(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post = post)

class NewPost(BaseHandler):
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
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "subject and content, please!"
            self.render("newpost.html", subject=subject, content=content, error=error)


def name_validation(username):
    name = re.match(r'^[a-zA-Z0-9_-]{3,20}$', username)
    return name and username


def password_validation(password):
    user_password = re.match(r'^.{3,20}$', password)
    return user_password and password


def verifypassword_validation(verifypassword):
    user_verify = re.match(r'^.{3,20}$', verifypassword)
    return user_verify 


def Email_validation(Email):
    email_id = re.match(r'^[\S]+@[\S]+.[\S]+$', Email)
    return email_id and Email

class Registration(BaseHandler):
    def get(self):
        self.render('registration.html')

    def post(self):
        self.name = self.request.get('name')
        self.password = self.request.get('password')
        self.verifypassword = self.request.get('verifypassword')
        self.email = self.request.get('email')

        username = name_validation(self.name)
        pass_word = password_validation(self.password)
        e_mail = Email_validation(self.email)
        error = False
        params = dict(name = self.name, email = self.email)

        if not username:
            params['error_username'] = "That is not a valid username"
            error = True

        if not pass_word:
            params['error_password'] = "That is not a valid password"
            error = True
        elif self.password != self.verifypassword:
            params['error_verify'] = "your password didn't match"
            error = True

        if not e_mail:
            params['error_email'] = "That is not a valid E-mail"
            error = True

        if error:
            self.render('registration.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Unit2Signup(Registration):
    def done(self):
        self.redirect('/welcome?name=' + self.name)

class Register(Registration):
    def done(self):
        u = User.by_name(self.name)
        if u:
            msg = 'That user already exists'
            self.render('registration.html', error_username = msg)
        else:
            u = User.register(self.name, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/unit3/welcome')


class Login(BaseHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        name = self.request.get('name')
        password = self.request.get('password')

        u = User.login(name, password)
        print name
        print password
        if u:
            print u
            self.login(u)
            self.redirect('/unit3/welcome')
        else:
            print "error"
            msg = 'Invalid login'
            self.render('login.html', error_login = msg)

class Logout(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/register')

class Unit3Welcome(BaseHandler):
    def get(self):
        if self.user:
            self.render('Welcome.html', name = self.user.name)
        else:
            self.redirect('/register')

class Welcome(BaseHandler):
    def get(self):
        name = self.request.get('name')
        if name_validation(name):
            self.render('Welcome.html', name = name)
        else:
            self.redirect('/unit2/signup')

app = webapp2.WSGIApplication([('/',MainPage),
                               ('/register', Register ),
                               ('/login', Login),
                               ('/logout',Logout),
                               ('/welcome', Welcome),
                               ('/unit3/welcome', Unit3Welcome),
                               ('/unit2/signup', Unit2Signup),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost)
                               ],debug = True)



        

