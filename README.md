# Blockchain-based E-voting
### Usage

1. Create virtual env and clone repo within
2. Run `pip install -r requirements.txt`
3. Locate `manage.py` file and for first time run : 
   > `python manage.py makemigrations`
   > `python manage.py`
4. Run `python manage.py runserver` to run the project and visit http:localhost:8000
5. Use block module to create and mine a voting block using private key in `bbvoting_project/demo_private.pem`
6. Use chain module to create and mine dummy votes.
