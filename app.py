from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-url', methods=['POST'])
def submit_url():
    base_url = request.form['base_url']
    # Here, you can add code to process the base URL or pass it to another function
    return f"Base URL submitted: {base_url}"

if __name__ == "__main__":
    app.run(debug=True)
