from app import create_app, socketio, db

app = create_app(debug=True)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    socketio.run(app)
