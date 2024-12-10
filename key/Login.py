from flask import Flask, request, render_template_string
import hashlib

app = Flask(__name__)

# HTML form for inputting username and password
HTML_FORM = '''
<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h2>Login</h2>
    <form method="post">
        <label for="username">Username:</label><br>
        <input type="text" id="username" name="username" required><br>
        <label for="password">Password:</label><br>
        <input type="password" id="password" name="password" required><br><br>
        <input type="submit" value="Submit">
    </form> 
</body>
</html>
'''

@app.route('/', methods=['GET'])
def login_form():
    return HTML_FORM

@app.route('/', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    # Hashing the password with MD5
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    # Saving the hashed password to a file
    with open("credentials.txt", "w") as file:
        file.write(f"{username}\n{hashed_password}")


    # Update the file 'offset' with the value 97 and add a new line
    with open("offset.txt", "w") as file:
        file.write("257")

    # Create an empty file named 'salt'
    with open("salt.txt", "w") as file:
        pass  # 'pass' is used here to perform no action, leaving the file empty

    return "Files saved"

if __name__ == '__main__':
    app.run(debug=True)
