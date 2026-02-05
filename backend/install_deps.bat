@echo off
cd /d C:\Users\hanso\in-a-lign\backend
call .venv\Scripts\activate.bat
pip install scikit-learn sentence-transformers torch --quiet
echo Installation complete!
pip list | findstr /i "scikit torch sentence"
