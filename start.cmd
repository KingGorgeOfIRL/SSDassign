call Scripts\activate.bat
call pip install -r requirements.txt
start chrome.exe http://127.0.0.1:8000/
call python MainPage/manage.py runserver 8000
cmd /k