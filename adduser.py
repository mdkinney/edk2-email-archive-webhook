## @file
# Command line utility to add first user to the application database
#
# Copyright (c) 2021, Intel Corporation. All rights reserved.<BR>
# SPDX-License-Identifier: BSD-2-Clause-Patent
#
##
'''
adduser
'''
import argparse
from datetime import datetime
from app      import create_app
from Models   import db, User

#
# Globals for help information
#
__prog__        = 'adduser'
__copyright__   = 'Copyright (c) 2021, Intel Corporation. All rights reserved.'
__description__ = 'Command line utility to add first user to the application database'

if __name__ == '__main__':
    #
    # Create command line argument parser object
    #
    parser = argparse.ArgumentParser (prog = __prog__,
                                      description = __description__ + __copyright__)
    parser.add_argument ("-u", "--username", dest = 'username', required = True,
                         help = "Usename of user to add to user database.")
    parser.add_argument ("-e", "--email", dest = 'email', required = True,
                         help = "Email address or user to add to user database.")
    parser.add_argument ("-p", "--password", dest = 'password', required = True,
                         help = "Password of user to add to user database.")
    parser.add_argument ("-f", "--firstname", dest = 'firstname', default = '',
                         help = "First name of user to add to user database.")
    parser.add_argument ("-l", "--lastname", dest = 'lastname', default = '',
                         help = "Last name of user to add to user database.")
    parser.add_argument ("-v", "--verbose", dest = 'verbose', action = "store_true",
                         help = "Increase output messages")
    parser.add_argument ("-q", "--quiet", dest = 'quiet', action = "store_true",
                         help = "Reduce output messages")
    parser.add_argument ("--debug", dest = 'debug', type = int, metavar = '[0-9]',
                         choices = range (0, 10), default = 0,
                         help = "Set debug level")

    #
    # Parse command line arguments
    #
    args = parser.parse_args ()

    app = create_app()
    with app.app_context():
        user = User.query.filter_by(username=args.username).first()
        if user:
            print ('adduser: Username {} already exists in the user database.'.format (args.username))
        else:
            hash = app.user_manager.hash_password(args.password)
            try:
                db.session.add (
                    User(username=args.username, active=True, email=args.email,
                        password=hash, email_confirmed_at=datetime.now(),
                        first_name=args.firstname, last_name=args.lastname
                        )
                    )
                db.session.commit()
                print ('adduser: Username {} added to the user database.'.format (args.username))
            except:
                print ('adduser: Error adding Username {} to the user database.  Email must be unique'.format (args.username))
                db.session.rollback()
                db.session.commit()
        print ('User List:')
        for user in User.query.all():
            print ('  ', user.username)
