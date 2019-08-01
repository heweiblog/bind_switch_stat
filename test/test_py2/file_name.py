
import datetime

def get_file_name(file_type):
	ctime = datetime.datetime.now()
	year = '%04d' % ctime.year
	month = '%02d' % ctime.month
	day = '%02d' % ctime.day
	operator, vender = 'ct', 'yamu'
	return file_type + '_' + operator + '_' + vender + '_' + year + month + day + '.gz'

print(get_file_name('root'))
