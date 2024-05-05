from json import dumps, loads
import logging
from tornado.web import RequestHandler

class BaseHandler(RequestHandler):
    @property
    def db(self):
        return self.application.db

    @property
    def executor(self):
        return self.application.executor

    def prepare(self):
        """Prepare method is called before each request."""
        if self.request.body:
            try:
                json_data = loads(self.request.body)
                self.request.arguments.update(json_data)
            except ValueError as e:
                logging.error(f"JSON parsing error: {str(e)}")
                self.send_error(400, message='Unable to parse JSON.')
        self.response = dict()

    def set_default_headers(self):
        """Sets default CORS and Content-Type headers for all responses."""
        self.set_header('Content-Type', 'application/json')
        self.set_header('Access-Control-Allow-Origin', '*')
        self.set_header('Access-Control-Allow-Methods', '*')
        self.set_header('Access-Control-Allow-Headers', '*')

    def write_error(self, status_code, **kwargs):
        """Custom error handling to ensure the response is in JSON format."""
        if 'message' not in kwargs:
            kwargs['message'] = 'Invalid HTTP method.' if status_code == 405 else 'Unknown error.'
        self.response = {key: str(value) if not isinstance(value, (dict, list, str, int, float, bool, type(None))) else value for key, value in kwargs.items()}
        self.write_json()

    def write_json(self, response=None):
        """Writes a JSON response. If no argument is provided, it uses the instance's response attribute."""
        try:
            output = dumps(response if response is not None else self.response)
            self.write(output)
        except TypeError as e:
            logging.error(f"Failed to serialize response: {response if response is not None else self.response}, error: {str(e)}")
            self.set_status(500)
            self.finish("Internal Server Error: Unable to serialize response.")
