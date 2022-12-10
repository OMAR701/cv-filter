import fitz
import docx2txt
import re
import pickle
from nltk.tokenize import word_tokenize
from nltk.corpus import stopwords

class jdExtractor:
	def __init__(self):
		self.STOPWORDS = set(stopwords.words('english') + ['``', "''"])

	def __clean_text(self, text):
		# convert to lovercase
		text = text.lower()
		# remove urls
		text = re.sub('http\S+\s*', ' ', text)
		# remove RT and cc
		text = re.sub('RT|cc', ' ', text)
		# remove hashtags
		text = re.sub('#\S+', ' ', text)
		# remove mentions
		text = re.sub('@\S+', ' ', text)
		# remove punctuations
		text = re.sub('[%s]' % re.escape("""!"#$%&'()*+,-/:;<=>?@[\]^_`{|}~"""), ' ', text)
		text = re.sub('[%s]' % re.escape("""."""), '', text)
		# 
		text = re.sub(r'[^\x00-\x7f]', r'', text)
		# remove extra whitespace
		text = re.sub('\s+', ' ', text)

		# tokenize
		text_tokens = word_tokenize(text)

		# remove stopwords
		filtered_text = [word for word in text_tokens if not word in self.STOPWORDS]

		return ' '.join(filtered_text)

	def extractData(self, file, extension):
		text = ""

		if extension == 'docx':
			temp = docx2txt.process(file)
			text = [line.replace('\t', ' ') for line in temp.split('\n')]
			text = ' '.join(text)
		elif extension == 'pdf':
			for page in fitz.open(file):
				text += str(page.get_text())
			text = ' '.join(text.split('\n'))

		return self.__clean_text(text)
