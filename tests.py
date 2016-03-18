#!/usr/bin/python3

# Package pour les tests


def singletest(test, **kwargs):
	for key, value in kwargs.items():
		locals()[str(key)] = value
	testresult = eval(test)
	if not testresult:
		raise Exception('Test failed: ' + str(test))
	print(test + ' : OK')
	return testresult
