set scriptpath=%~dp0
call Scripts\activate.bat
call pip install -r requirements.txt
call python MainPage/manage.py runsslserver --certificate %scriptpath%\Lib\site-packages\sslserver\certs\development.crt --key %scriptpath%\Lib\site-packages\sslserver\certs\development.key
cmd /k
