from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import json
import re
import pickle
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow import keras
import numpy as np

class resumeCategorizer:
	
	def __init__(self):
		self.STOPWORDS = set(stopwords.words('english') + ['``', "''"])
		self.max_length = 500
		self.trunc_type = 'post'
		self.padding_type = 'post'

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

	def screenResume(self, text):
		# get feature text tokenizer used for model training
		with open('assets/tokenizer/feature_tokenizer.pickle', 'rb') as handle:
			feature_tokenizer = pickle.load(handle)

		# get label encoding dictionary from model training
		with open('assets/dictionary/dictionary.pickle', 'rb') as handle:
			encoding_to_label = pickle.load(handle)

		# handle unknown label case
		encoding_to_label[0] = 'unknown'

		# get original labels
		with open('assets/data/labels.json', 'r') as file:
			original_labels = json.load(file)

		cleaned_text = self.__clean_text(text)

		# convert user input to padded sequence
		predict_sequence = feature_tokenizer.texts_to_sequences([cleaned_text])
		predict_padded = pad_sequences(predict_sequence, maxlen=self.max_length, padding=self.padding_type, truncating=self.trunc_type)
		predict_padded = np.array(predict_padded)

		# load mode and make prediction
		model = keras.models.load_model('assets/new_model/model.h5')
		prediction = model.predict(predict_padded)

		# get encoding of top 5 results
		encodings = np.argpartition(prediction[0], -5)[-5:]
		encodings = encodings[np.argsort(prediction[0][encodings])]
		encodings = reversed(encodings)

		category = {}

		# send results of top 5 encodings and confidences to output
		for encoding in encodings:
			label = encoding_to_label[encoding]
			probability = prediction[0][encoding] * 100
			probability = round(probability, 2)
			category[original_labels[label]] = probability

		return category