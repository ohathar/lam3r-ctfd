#!/usr/bin/env python3

###### FUGLY SQLITE ISH CAUSE DONE ON ROADTRIP ########
import sqlite3, time, os, binascii
from passlib.hash import bcrypt
from flask import Flask
from flask import abort
from flask import flash
from flask import g
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import session
from flask import url_for
from flask import send_from_directory

app = Flask(__name__)

DATABASE = './app.example.db'
app.secret_key = binascii.hexlify(os.urandom(32))

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d

def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = sqlite3.connect(DATABASE)
		db.row_factory = dict_factory
	return db

@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.close()

def user_exists(username):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id FROM users WHERE username = ? LIMIT 1',(username.lower(),))
		res = cur.fetchone()
		if res is not None:
			return True
		return False
	except Exception as e:
		print(e)
		return False

def register(username, password):
	if user_exists(username):
		return {'status': False, 'message': 'UserName Exists'}
	if password == '':
		return {'status': False, 'message': 'Password Too $hort'}
	if username == '':
		return {'status': False, 'message': 'Username Too $hort'}
	if len(username) > 25: # arbitrary length
		return {'status': False, 'message': 'Username Too L0ng'}
	try:
		cur = get_db().cursor()
		cmd = '''INSERT INTO users (username, password, score) VALUES (?, ?, 0)'''
		password_hash = bcrypt.encrypt(password, rounds=8)
		cur.execute(cmd,(username,password_hash))
		cur.connection.commit()
		login(username,password)
		return {'status': True, 'message': 'Registration Successful'}
	except Exception as e:
		print(e)
		return {'status': False, 'message': str(e)}


def login(username,password):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id, username, password FROM users WHERE username = ? LIMIT 1', (username,))
		res = cur.fetchone()
		if res is None:
			return False
		if not bcrypt.verify(password,res.get('password')):
			return False
		session['userid'] = res.get('id')
		return True
	except Exception as e:
		print(e)
		return False

def is_logged_in():
	return True if session.get('userid') else False

def get_user_solved(userid):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT challengeid FROM scoreboard WHERE userid = ?', (userid,))
		res = cur.fetchall()
		print('get_user_solved out:', repr(res))
		return res if res is not None else []
	except Exception as e:
		print(e)
		return {'fuck': 'shit'}

def get_challenges():
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id, name, description, points FROM challenges ORDER BY points, id ASC')
		res = cur.fetchall()
		return res if res is not None else {'fuck': 'shit'}
	except Exception as e:
		print(e)
		return {'fuck': 'shit'}

def is_legit_problem(problem_id):
	challs = get_challenges()
	if problem_id in [str(chall['id']) for chall in challs]:
		return True
	return False

def get_flag(problem_id):
	try:
		cur = get_db().cursor()
		cur.execute('SELECT id, flag FROM challenges WHERE id = ? LIMIT 1', (problem_id,))
		res = cur.fetchone()
		if res == '':
			return {'status': False, 'message': 'Unknown Problem'}
		return res
	except Exception as e:
		print(e)
		return {'fuck': 'shit'}

def award_solve(problem_id):
	try:
		userid = session.get('userid')
		cur = get_db().cursor()
		challs = get_challenges()
		points = 0
		now = int(time.time())
		for chall in challs:
			if str(chall.get('id')) == problem_id:
				points = chall.get('points')
				break
		cmd = '''INSERT INTO scoreboard (userid, challengeid, points, occured) VALUES (?,?,?,?)'''
		cur.execute(cmd, (userid,problem_id, points, now))
		cmd = '''UPDATE users SET score = score + ? WHERE id = ? LIMIT 1'''
		cur.execute(cmd, (points, userid))
		cur.connection.commit()
		return True
	except Exception as e:
		print(e)
		return False

def grade_flag(problem_id,userid,send_flag):
	if problem_id in [str(x.get('challengeid')) for x in get_user_solved(session.get('userid'))]:
		print('already solved')
		return {'status': False, 'message': 'Already Solved'}
	if not is_legit_problem(problem_id):
		print('Non-existent problem')
		return {'status': False, 'message': 'Non-existent Problem'}
	flag_status = get_flag(problem_id)
	if send_flag == flag_status.get('flag'):
		print('looks good, award them...')
		award_solve(problem_id)
		return {'status': True}
	print(repr(send_flag),flag_status.get('flag'))
	return {'status': False, 'message': 'Incorrect Flag'}

def get_scores():
	try:
		cur = get_db().cursor()
		cur.execute('SELECT username, score FROM users ORDER BY score DESC')
		return cur.fetchall()
	except Exception as e:
		print(e)
		return [{'username': 'nope', 'score': -999999}]

@app.route('/scores')
def scores_route():
	score_data = get_scores()
	return render_template('scores.html',score_data=score_data)


@app.route('/problems', methods=['GET','POST'])
def problems_route():
	if not is_logged_in():
		return redirect(url_for('index_route'))
	message = ''
	user_solved = [x.get('challengeid') for x in get_user_solved(session.get('userid'))]
	if request.method == 'POST':
		try:
			if grade_flag(request.form.get('problem_id'),session.get('userid'),request.form.get('send_flag')).get('status'):
				message = 'congrats, solved'
				user_solved = get_user_solved(session.get('userid'))
			else:
				message = 'nope, sorry'
		except Exception as e:
			print(e)
			message = 'uhhhhh....'
	problem_data = get_challenges()
	print(repr(problem_data))
	print(user_solved)
	return render_template('problems.html',problem_data=problem_data,user_solved=user_solved,message=message)

@app.route('/logout')
def logout_route():
	session.clear()
	return redirect(url_for('index_route'))

@app.route('/')
def index_route():
	return render_template('main.html')

@app.route('/login', methods=['GET','POST'])
def login_route():
	message = ''
	if request.method == 'POST':
		if request.form.get('submit') == 'login':
			if login(request.form.get('username',''), request.form.get('password','')):
				return redirect(url_for('index_route'))
			else:
				message = 'Sorry, Nope'
		elif request.form.get('submit') == 'register':
			status = register(request.form.get('username','').strip(), request.form.get('password','').strip())
			if status.get('status'):
				return redirect(url_for('index_route'))
			else:
				message = status.get('message')
	return render_template('login.html',message=message)

if __name__ == "__main__":
	app.run(host='0.0.0.0',port=9005)

