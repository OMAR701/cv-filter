from flask import Blueprint, render_template, request, redirect, session, jsonify
from database import mongo
from werkzeug.utils import secure_filename
from jdExtractor import jdExtractor
from bson.objectid import ObjectId
from datetime import datetime
import pickle
import os

employer = Blueprint('employer', __name__, static_folder='static', template_folder='templates')
JD_FOLDER = 'static/job_descriptions'

# --------------------------- Database Collections --------------------------- #
Jobs = mongo.db.Jobs
AppliedUsers = mongo.db.AppliedUsers
Resumes = mongo.db.Resumes
TopSkills = mongo.db.TopSkills
Users = mongo.db.Users
# --------------------------- Database Collections --------------------------- #

# ----------------------------- ML pickel import ----------------------------- #
jdExtractorObj = pickle.load(open('jdExtractor.pkl', 'rb'))
# ----------------------------- ML pickel import ----------------------------- #

@employer.route('/')
def home():
	if 'user_id' in session and 'user_name' in session:
		if session['profile'] == 'employer':
			return render_template('employer_dashboard.html')
		else:
			return redirect('/applicant')
	else:
		return redirect('/')

def getExtension(filename):
	return filename.rsplit('.',1)[1].lower()

def allowedExtension(filename):
	permittedExtension = ['docx', 'pdf']
	return '.' in filename and getExtension(filename) in permittedExtension

@employer.route('/post_job')
def post_job():
	fetched_jobs = Jobs.find(
		{},
		{
			'_id': 1,
			'job_profile': 1,
			'company_name': 1,
			'created_at': 1,
			'jd_filename': 1,
			'last_date': 1,
			'salary': 1,
			'user_id': 1,
		}
	).sort([('created_at', -1)])

	if fetched_jobs == None:
		render_template('post_job.html', errorMsg="Problem in Jobs Fetch")
	else:
		jobs = {}
		count = 0
		for job in fetched_jobs:
			print(job)
			#if 'user_id' in session == job['user_id']:
			jobs[count] = {
				'job_id': job['_id'],
				'job_profile': job['job_profile'],
				'company_name': job['company_name'],
				'created_at': job['created_at'],
				'jd_filename': job['jd_filename'],
				'last_date': job['last_date'],
				'salary': job['salary']
			}
			count += 1

		return render_template('post_job.html', len=len(jobs), data=jobs)

@employer.route('/add_job', methods=['POST'])
def add_job():
	try:
		file = request.files['jd']
		
		job_profile = str(request.form.get('job_profile'))
		company_name = str(request.form.get('company_name'))
		last_date = str(request.form.get('last_date'))
		salary = str(request.form.get('salary'))
		
		filename = secure_filename(file.filename)
		file.save(os.path.join(JD_FOLDER, filename))
		
		job_description = jdExtractorObj.extractData(JD_FOLDER + '/' + filename, getExtension(file.filename))

		result = Jobs.insert_one({
			'job_id': ObjectId(),
			'job_profile': job_profile,
			'job_description': job_description,
			'company_name': company_name,
			'created_at': datetime.now(),
			'jd_filename': filename,
			'last_date': last_date,
			'salary': salary,
			'user_id': 'user_id' in session
		})

		if result == None:
			return render_template('post_job.html', errorMsg='Job Add Error Occured')
		else:
			return redirect('/employer/post_job')
	except:
		print('Job Creation Exception occured')

@employer.route('/view_applied_candidates', methods=['POST', 'GET'])
def view_applied_candidates():

	job_id = request.form['job_id']

	data = AppliedUsers.find(
		{'job_id': ObjectId(job_id)},
		{
			'user_id': 1,
			'user_name': 1,
			'matching_percentage': 1,
		}
	).sort([('matching_percentage', -1)])

	resumes = Resumes.find(
		{},
		{
			'user_id': 1,
			'resume_title': 1
		}
	)

	data = list(data)
	resumes = list(resumes)

	for applicant in data:
		for resume in resumes:
			if applicant['user_id'] == resume['user_id']:
				applicant['resume_title'] = resume['resume_title']

	if data == None:
		return jsonify({'status_code':400, 'message': 'problem in fetching data'})
	else:
		
		result = {}
		count = 0
		result[1] = 200
		for applicant in data:
			result[count+2] = {
				'name': applicant['user_name'],
				'match': applicant['matching_percentage'],
				'resume': applicant['resume_title']
			}
			count += 1
		result[0] = count

		return result

@employer.route('/empSearch', methods=['POST'])
def empSearch():
	category = str(request.form.get('category'))
	
	topEmployees = TopSkills.find(
		{'top_skills.' + category: {'$ne': None}},
		{'top_skills.' + category: 1, 'user_id': 1}
	).sort([('top_skills.' + category, -1)])

	if topEmployees == None:
		return render_template('employer_dashboard.html', errorMsg='Problem in category fetch')
	else:
		selectedResume = {}
		count = 0
		
		for emp in topEmployees:
			data = Users.find_one(
				{'_id': ObjectId(emp['user_id'])},
				{'_id': 1, 'name': 1, 'email': 1}
			)
			selectedResume[count] = {
				'_id': data['_id'],
				'name': data['name'],
				'email': data['email']
			}
			count += 1

		return render_template('employer_dashboard.html', len=len(selectedResume), data=selectedResume)

@employer.route('/viewDetails', methods=['POST', 'GET'])
def viewDetails():
	employee_id = request.form['employee_id']
	result = Resumes.find({ 'user_id' : ObjectId(employee_id) })
	data = result[0]
	result = {
		'name': data['name'],
		'email': data['email'],
		'mobile_number': data['mobile_number'],
		'skills': data['skills'],
		'education': data['education']
	}

	return jsonify(result)