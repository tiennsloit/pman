### Project Info
A tiny tool like Postman to test api

### Notes
- **Python Version**: The script should work with Python 3.6+ (tested with 3.11 based on your previous interactions). Ensure this is clear in the README.
- **Optional Virtual Environment**: You can suggest using a virtual environment for isolation:
-   #### Optional: Use a Virtual Environment
  ```markdown
    python -m venv venv
    source venv/bin/activate  # macOS
    venv\Scripts\activate     # Windows
    pip install PyQt5 requests

- **Troubleshooting**: Add a note about common issues:
- If `pip` fails, ensure it's updated: `pip install --upgrade pip`.
- On macOS, if you see permission errors, try `pip install --user` or use `sudo`.
- On Windows, ensure Python is in your PATH (check with `python --version`).
- Verify module installation with `pip show PyQt5 requests`.

## Packaging and Distribution (Python Package)

To distribute the `p.py` script as a Python package, use `setuptools` to create a `pip`-installable package. This requires Python 3.6+ on the target computer.

### Steps to Package
1. **Create Project Files**:
   - `requirements.txt`:
PyQt5>=5.15.6
requests>=2.28.0

2. **Install Build Tools**:
    ```markdown
    pip install setuptools wheel

3. **Create the Package:Navigate to the project directory:**:
    
    ```markdown
    python3 setup.py sdist bdist_wheel
4. **Test locally**
    ```markdown
    pip install .
5. **Install on Windows for testing**
    ```markdown
    pip install pman_tester-1.0.0-py3-none-any.whl
6. **Add environment for Windows**
    ```markdown
    C:\Users\%USERNAME%\AppData\Local\Programs\Python\Python311\Script
    C:\Users\%USERNAME%\AppData\Roaming\Python\Python313\Scripts\pman_tester.exe
7. **Upload to cloud**    
    ```markdown
    pip install twine
8. **Test Cloud** https://test.pypi.org/account/register/
    ```markdown
    twine upload --repository testpypi dist/*
    pip install --index-url https://test.pypi.org/simple/ pman_tester
    pman-tester
9. **Product Cloud**
    ```markdown
    twine upload dist/*
10. **Check Path**
    ```markdown
    pip show pman_tester
11. **Install**
    ```markdown
    pip install pman_tester
12. **Upgrade wont work =))**
I am sure your current setting will not be lost
13. **Uninstall and reinstall**
    ```markdown
    pip uninstall pman_tester
    pip install pman_tester