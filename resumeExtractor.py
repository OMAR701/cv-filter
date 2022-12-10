from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
from nltk import everygrams
import re
import pandas as pd
import spacy
from spacy.matcher import Matcher
import fitz, docx2txt
import pickle

class resumeExtractor:

	def __init__(self):
		self.STOPWORDS = set(stopwords.words('english') + ['``', "''"])
		self.EDUCATION = [
			'BE', 'BTECH', 'BSC', 'BS', 'BCA', 'BCOM',
			'ME', 'MS', 'MTECH', 'MCA',
			'DIPLOMA', '12TH', '10TH',
			'SSC', 'HSC', 'CBSE', 'ICSE', 'X', 'XII'
		]
		self.data = pd.read_csv("assets/data/newskill2.csv")
		self.SKILL_DB = list(self.data.columns.values)
		self.nlp = spacy.load('en_core_web_lg')
		self.matcher = Matcher(self.nlp.vocab)
	
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
		filtered_text = [word for word in text_tokens if word in self.EDUCATION or not word in self.STOPWORDS]

		return ' '.join(filtered_text)

	def __extract_name(self, text):
		nlp_text = self.nlp(text)

		# POS - part of speech & PROPN - proper noun
		pattern = [{'POS': 'PROPN'}]

		self.matcher.add('NAME', [pattern])

		matches = self.matcher(nlp_text)

		for match_id, start, end in matches:
			span = nlp_text[start:end+1]
			return span.text
	
	def __extract_mobile_number(self, text):
		# get list of numbers in text
		phone = re.findall(re.compile(r'(?:(?:\+?([1-9]|[0-9][0-9]|[0-9][0-9][0-9])\s*(?:[.-]\s*)?)?(?:\(\s*([2-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9])\s*\)|([0-9][1-9]|[0-9]1[02-9]|[2-9][02-8]1|[2-9][02-8][02-9]))\s*(?:[.-]\s*)?)?([2-9]1[02-9]|[2-9][02-9]1|[2-9][02-9]{2})\s*(?:[.-]\s*)?([0-9]{4})(?:\s*(?:#|x\.?|ext\.?|extension)\s*(\d+))?'), text)
		if phone:
			number = ''.join(phone[0])
			if len(number) > 10:
				return '+' + number
			else:
				return number
	
	def __extract_email(self, text):
		# get email from text
		email = re.findall("([^@|\s]+@[^@]+\.[^@|\s]+)", text)
		if email:
			try:
				return email[0].split()[0].strip(';')
			except IndexError:
				return None

	def __extract_eduaction(self, text):
		nlp_text = self.nlp(text)

		# sentence tokenizer
		nlp_text = [str(sent).strip() for sent in nlp_text.sents]
		edu = dict()

		# extract education degree
		for index, texts in enumerate(nlp_text):
			for text in texts.split():
				# replace all special symbols
				text = re.sub(r'[?|$|.|!|,|(|)]', r'', text)
				if text.upper() in self.EDUCATION and text not in self.STOPWORDS:
					edu[text] = text + nlp_text[index]
		
		# seperate year
		education = []
		for key in edu.keys():
			year = re.search(re.compile(r'(((20|19)(\d{2})))'), edu[key])
			if year:
				education.append((key, ''.join(year[0])))
			else:
				education.append(key)
		
		return education

	def __extract_skills(self, text):
		stop_words = set(stopwords.words('english'))
		word_tokens = word_tokenize(text)

		# remove stop words
		filtered_tokens = [word for word in word_tokens if word not in stop_words]

		# remove punctuation
		filtered_text = [word for word in word_tokens if word.isalpha()]

		# generate bigrams and trigrams (auch as AI)
		bigrams_trigrams = list(map(' '.join, everygrams(filtered_tokens, 2, 3)))

		# results
		found_skills = set()

		# search for each token in our skill database
		for token in filtered_tokens:
			if token.lower() in self.SKILL_DB:
				found_skills.add(token)
		
		# search for each bigram and trigram in our skills database
		for ngram in bigrams_trigrams:
			if ngram in self.SKILL_DB:
				found_skills.add(ngram)
		
		return found_skills

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
		
		name = self.__extract_name(text)
		mobile_no = self.__extract_mobile_number(text)
		email = self.__extract_email(text)
		text = self.__clean_text(text)
		skills = self.__extract_skills(text)
		education = self.__extract_eduaction(text)

		return (name, mobile_no, email, education, skills, text)
