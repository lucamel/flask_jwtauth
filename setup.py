"""
Flask-JWTAuth
-------------

This is the description for that library
"""
from setuptools import setup, find_packages


setup(
    name='Flask-JWTAuth',
    version='0.1',
    url='https://github.com/lucamel/flask_jwtauth',
    license='BSD',
    author='Luca Melgrati',
    author_email='luca@lucamel.me',
    description='JWT Auth for Flask',
    long_description=__doc__,
    packages=['flask_jwtauth'],
    # if you would be using a package instead use packages instead
    # of py_modules:
    # packages=['flask_jwtauth'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask', 'PyJWT'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)