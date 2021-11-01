# Django NextJs integration with JWT
==================================

Django NextJs integration with JWT

![Black code style](https://img.shields.io/badge/code%20style-black-000000.svg "Black code style")

Technologies used for backend:
- Django
- Django Rest Framework
- Simple JWT

Technologies used for the frontend:
- ReactJS
- NextJS
- Redux
- Chakra UI


## Getting Up and Running Locally
1. Create a virtualenv
1. Activate the virtualenv
1. Clone the repo
1. cd backend
1. pip install -r requirements/local.txt
1. createdb  < database_name >
1. export DATABASE_URL=postgres://postgres:< password >@127.0.0.1:5432/< database_name >
1. export CELERY_BROKER_URL=redis://localhost:6379/0
1. export USE_DOCKER=no
1. If you want to use Gmail, you can use:
   export EMAIL_URL=smtp://< your_email_address >:< password >@smtp.gmail.com:465/?ssl=True
   (You may need to change the settings for "Less secure apps" of your Gmail account)
1. python manage.py migrate
1. python manage.py runserver 0.0.0.0:8000
