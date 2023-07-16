call Scripts\activate.bat
start chrome.exe http://127.0.0.1:8000/
call python MainPage/manage.py runserver
cmd /k