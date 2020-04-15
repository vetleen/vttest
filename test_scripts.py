import os
if '/app' in os.environ['HOME']:
    import django_heroku
    django_heroku.settings(locals())
