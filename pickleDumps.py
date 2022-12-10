from jdExtractor import jdExtractor
from resumeExtractor import resumeExtractor
from resumeCategorizer import resumeCategorizer
from jdResumeComparision import jdResumeComparision
import pickle

# jdExtractor1 = jdExtractor()
# pickle.dump(jdExtractor1, open('jdExtractor.pkl', 'wb'))

resumeCategorizer1 = resumeCategorizer()
pickle.dump(resumeCategorizer1, open("resumeCategorizer.pkl","wb"))

# resumeExtractor1 = resumeExtractor()
# pickle.dump(resumeExtractor1, open("resumeExtractor.pkl","wb"))

# jdResumeComparision1 = jdResumeComparision()
# pickle.dump(jdResumeComparision1, open('jdResumeComparision.pkl', 'wb'))
