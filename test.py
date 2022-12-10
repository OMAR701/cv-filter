from resumeExtractor import resumeExtractor
from resumeCategorizer import resumeCategorizer
from jdExtractor import jdExtractor
from jdResumeComparision import jdResumeComparision

if __name__ == "__main__":
	
	resumeExtractor = resumeExtractor()
	data = resumeExtractor.extractData('assets/resume/vaibhav resume.pdf', 'pdf')
	resumeData = data[5]
	
	jdExtractor = jdExtractor()
	jobDescData = jdExtractor.extractData('assets/job_desc/python job desc.pdf', 'pdf')
	
	jdResumeComparision = jdResumeComparision()
	score = jdResumeComparision.match(jobDescData, resumeData)
	
	resumeScreen = resumeCategorizer()
	categories = resumeScreen.screenResume(resumeData)
	
	print("\n---------------------------- Resume Screening ----------------------------")
	print(data)
	print("---------------------------- Resume Screening ----------------------------\n")

	print("\n----------------------------- Job Decription -----------------------------")
	print(jobDescData)
	print("----------------------------- Job Decription -----------------------------\n")

	print("\n--------------------------- JD Resume Scoring ----------------------------")
	print("Match Percentage : " + str(score) + "%")
	print("--------------------------- JD Resume Scoring ----------------------------\n")
	
	print("\n---------------------------- Job Categorizer -----------------------------")
	print(categories)
	print("---------------------------- Job Categorizer -----------------------------\n")