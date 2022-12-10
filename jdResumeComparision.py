from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import CountVectorizer
import pickle

class jdResumeComparision:

	def __matcher(self, job_desc, resume_text):
		data = [resume_text, job_desc]
		cv = CountVectorizer()
		count_matrix = cv.fit_transform(data)
		match_percentage = cosine_similarity(count_matrix)[0][1] * 100

		return round(match_percentage, 2)

	def match(self, jd, resume):
		return self.__matcher(jd, resume)
