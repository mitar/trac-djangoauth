from trac.core import *
from trac.config import Option
from trac.util.translation import _
from trac.web.api import IRequestFilter, ITemplateStreamFilter

from genshi.builder import tag
from genshi.filters.transform import Transformer

from django.contrib import auth
from django.contrib.auth import models

from acct_mgr.api import IPasswordStore

class DjangoAuth(Component):
    """
    This class implements authentication against Django.
    """

    name_and_email_change_url = Option('account-manager', 'name_and_email_change_url', None,
        """URL of Django profile (name and email address) change form.""")
    reset_password_url = Option('account-manager', 'reset_password_url', None,
        """URL of Django password recovery form.""")

    implements(IPasswordStore, ITemplateStreamFilter, IRequestFilter)

    def _update_session_attributes(self, users):
        db = self.env.get_db_cnx()

        for user in users:
            try:
                cursor = db.cursor()
                cursor.execute("""INSERT INTO session (sid, last_visit, authenticated) VALUES (%s, 0, 1)""",
                                  (
                                      user.username,
                                  )
                              )
                db.commit()
            except:
                # We simply ignore this one
                db.rollback()

            try:
                cursor = db.cursor()
                cursor.execute("""DELETE FROM session_attribute WHERE sid=%s AND authenticated=%s AND name=%s;
                                  INSERT INTO session_attribute (sid, authenticated, name, value) VALUES (%s, %s, %s, %s);
                                  DELETE FROM session_attribute WHERE sid=%s AND authenticated=%s AND name=%s;
                                  INSERT INTO session_attribute (sid, authenticated, name, value) VALUES (%s, %s, %s, %s)""",
                                  (
                                      user.username, 1, 'name', user.username, 1, 'name', user.get_full_name(),
                                      user.username, 1, 'email', user.username, 1, 'email', user.email,
                                  )
                              )
                db.commit()
            except Exception, e:
                self.log.warn('DjangoAuth: exception in _update_session_attributes for %s: %s', user.username, e)
                db.rollback()

    # IPasswordStore methods

    def get_users(self):
        """
        Returns an iterable of the known usernames.
        """

        users = models.User.objects.filter(is_active=True).order_by('username')

        self._update_session_attributes(users)

        for user in users:
            yield user.username

    def has_user(self, user):
        """
        Returns whether the user account exists.
        """

        users = models.User.objects.filter(username__iexact=user, is_active=True)

        self._update_session_attributes(users)

        return users.exists()

    def has_email(self, address):
        """
        Returns whether a user account with that email address exists.
        """

        users = models.User.objects.filter(email__iexact=address, is_active=True)

        self._update_session_attributes(users)

        return users.exists()

    def set_password(self, user, password, old_password=None, name=None, email=None):
        """
        Sets the password for the user.  This should create the user account
        if it doesn't already exist.
        Returns True if a new account was created, False if an existing account
        was updated.
        """
        
        if self.has_user(user):
            # It will throw an exception if there are multiple users with the same username, but different character case
            user = models.User.objects.get(username__iexact=user, is_active=True)
            user.set_password(password)
            user.save()
            self._update_session_attributes([user])
            return False
        else:
            if email is None:
                email = ''
            # There is a race condition here for usernames with different character case, but we are ignoring it
            user = models.User.objects.create_user(username=user, email=email, password=password)
            if name is not None:
                parts = name.split(' ', 1)
                if len(parts) == 1:
                    user.first_name = name.strip()
                else:
                    user.first_name = parts[0].strip()
                    user.last_name = parts[1].strip()
                user.save()
            self._update_session_attributes([user])
            return True

    def check_password(self, user, password):
        """
        Checks if the password is valid for the user.
    
        Returns True if the correct user and password are specfied.  Returns
        False if the incorrect password was specified.  Returns None if the
        user doesn't exist in this password store. Instead of True it can
        also return the username of the user (to assure correct character
        case).

        Note: Returing `False` is an active rejection of the login attempt.
        Return None to let the auth fall through to the next store in the
        chain.
        """

        user = auth.authenticate(username=user, password=password)
        if user and user.is_active:
            self._update_session_attributes([user])
            return user.username
        else:
            return None

    def delete_user(self, user):
        """
        Deletes the user account.
        Returns True if the account existed and was deleted, False otherwise.
        """

        return models.User.objects.filter(username__iexact=user, is_active=True).update(is_active=False) != 0

    # IRequestFilter methods

    def pre_process_request(self, req, handler):
        """
        Called after initial handler selection, and can be used to change
        the selected handler or redirect request.
        """

        if self.reset_password_url and req.path_info == '/reset_password':
            req.redirect(self.reset_password_url)

        # Reverts any possible change to email and name
        if req.path_info == '/prefs' and req.authname != 'anonymous':
            req.args['name'] = req.session.get('name', '')
            req.args['email'] = req.session.get('email', '')

        return handler

    def post_process_request(req, template, content_type):
        """
        Do any post-processing the request might need; typically adding
        values to req.hdf, or changing template or mime type.
        """

        return (template, content_type)

    def post_process_request(req, template, data, content_type):
        """
        Do any post-processing the request might need; typically adding
        values to the template `data` dictionary, or changing template or
        mime type.
        """

        return (template, data, content_type)

    # ITemplateStreamFilter methods

    def filter_stream(self, req, method, filename, stream, data):
        """
        Returns changed stream for `prefs_general.html` template with notification
        opt-out preference option.

        `req` is the current request object, `method` is the Genshi render
        method (xml, xhtml or text), `filename` is the filename of the template
        to be rendered, `stream` is the event stream and `data` is the data for
        the current template.
        """

        if filename == 'prefs_general.html' and req.authname != 'anonymous':
            stream |= Transformer(".//table//input[@name='name']").attr('readonly', 'readonly')
            stream |= Transformer(".//table//input[@name='email']").attr('readonly', 'readonly')
            if self.name_and_email_change_url:
                stream |= Transformer('.//table').after(
                    tag.p(
                        _('You can change your name and email address '),
                        tag.a(_('here'), href=self.name_and_email_change_url),
                        '.',
                        **{'class': 'hint'}
                    )
                )
        return stream
