from flask import Blueprint, render_template, request, redirect, session, jsonify
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from database import mongo
from resumeExtractor import resumeExtractor
from resumeCategorizer import resumeCategorizer
from jdResumeComparision import jdResumeComparision
import os
import pickle
applicant = Blueprint('applicant', __name__, static_folder='static', template_folder='templates')
RESUME_FOLDER = 'static/resumes/'

# ------------------------- MongoDB Atlas Configuration start --------------------------- #
Users = mongo.db.Users
Resumes = mongo.db.Resumes
Jobs = mongo.db.Jobs
TopSkills = mongo.db.TopSkills
AppliedUsers = mongo.db.AppliedUsers
# -------------------------- MongoDB Atlas Configuration end ---------------------------- #

# ----------------------------- ML pickel import ----------------------------- #
extractorObj = pickle.load(open('resumeExtractor.pkl', 'rb'))
categorizerObj = pickle.load(open('resumeCategorizer.pkl', 'rb'))
jdResumeComparisionObj = pickle.load(open('jdResumeComparision.pkl', 'rb'))
# ----------------------------- ML pickel import ----------------------------- #

def getExtension(filename):
	return filename.rsplit('.',1)[1].lower()

def allowedExtension(filename):
	permittedExtension = ['docx', 'pdf']
	return '.' in filename and getExtension(filename) in permittedExtension

@applicant.route('/')
def home():
	if 'user_id' in session and 'user_name' in session:
		if session['profile'] == 'applicant':
			return render_template('applicant_dashboard.html')
		else:
			return redirect('/employer')
	else:
		return redirect('/')

@applicant.route('/uploadResume', methods=['POST'])
def uploadResume():
	if 'user_id' in session and 'user_name' in session:
		# try:
			file = request.files['resume']
			filename = secure_filename(file.filename)
			if file and allowedExtension(file.filename):
				temp = Resumes.find_one(
					{'user_id': ObjectId(session['user_id'])}, 
					{'resume_title': 1}
				)
				if temp == None:
					pass
				else:
					Resumes.delete_one(
						{'user_id': ObjectId(session['user_id'])},
					)
					TopSkills.delete_one(
						{'user_id': ObjectId(session['user_id'])}, 
					)
					os.remove(os.path.join(RESUME_FOLDER, temp['resume_title']))
				file.save(os.path.join(RESUME_FOLDER, filename))
				fetchedData = extractorObj.extractData(RESUME_FOLDER + filename, getExtension(filename))
				skillsPercentage = categorizerObj.screenResume(fetchedData[5])

				result = Resumes.insert_one({
					'user_id': ObjectId(session['user_id']),
					'name': fetchedData[0],
					'mobile_number': fetchedData[1],
					'email': fetchedData[2],
					'education': fetchedData[3],
					'skills': list(fetchedData[4]),
					'appear': 0,
					'resume_title': filename,
					'resume_data': fetchedData[5]
				})

				if result == None:
					return render_template('applicant_dashboard.html', errorMsg='Problem in Resume Data Storage')
				else:
					result = TopSkills.insert_one({
						'user_id': ObjectId(session['user_id']),
						'top_skills': dict(skillsPercentage)
					})

					if result == None:
						return render_template('applicant_dashboard.html', errorMsg='Problem in skills data storage')
					else:
						return render_template('applicant_dashboard.html', successMsg='Resume Screening successful')
			else:
				return render_template('applicant_dashboard.html', errorMsg='Document type not allowed')
		# except:
		# 	print('Resume Upload Failed')
		# 	return render_template('applicant_dashboard.html', errorMsg='Resume Upload Failed')
	else:
		return render_template('index.html', errorMsg='Login First')

@applicant.route('/show_job')
def show_job():
	fetched_jobs = Jobs.find(
		{},
		{
			'_id': 1,
			'job_profile': 1,
			'company_name': 1,
			'created_at': 1,
			'jd_filename': 1,
			'last_date': 1,
			'salary': 1
		}
	).sort([('created_at', -1)])

	appliedJobs = AppliedUsers.find(
		{'user_id': ObjectId(session['user_id'])},
		{'job_id': 1}
	)

	appliedJobs = [ x.get('job_id') for x in appliedJobs ]

	if fetched_jobs == None:
		return render_template('all_jobs.html', errorMsg='Problem in jobs fetched')
	else:
		jobs = {}
		count = 0

		for job in fetched_jobs:
			applied = 'not applied'
			if job['_id'] in appliedJobs:
				applied = 'applied'
			jobs[count] = {
				'job_id': job['_id'],
				'job_profile': job['job_profile'],
				'company_name': job['company_name'],
				'created_at': job['created_at'],
				'jd_filename': job['jd_filename'],
				'last_date': job['last_date'],
				'salary': job['salary'],
				'applied': applied
			}
			count += 1

		return render_template('all_jobs.html', len=len(jobs), data=jobs)

@applicant.route('/apply_job', methods=['POST'])
def apply_job():
	job_id = request.form['job_id']
	jd_data = Jobs.find_one(
		{'_id': ObjectId(job_id)},
		{'job_description': 1}
	)
	emp_data = Resumes.find_one(
		{'user_id': ObjectId(session['user_id'])},
		{'resume_data': 1}
	)

	if emp_data == None:
		return jsonify({'status_code':400, 'message': 'Please upload resume before applying'})

	match_percentage = jdResumeComparisionObj.match(str(jd_data['job_description']), str(emp_data['resume_data']))

	result = AppliedUsers.insert_one({
		'job_id': ObjectId(job_id),
		'user_id': ObjectId(session['user_id']),
		'user_name': session['user_name'],
		'matching_percentage': match_percentage
	})

	if result == None:
		return jsonify({'status_code':400, 'message': 'problem in applying'})
	else:
		return jsonify({'status_code':200, 'message': 'applied successfully'})