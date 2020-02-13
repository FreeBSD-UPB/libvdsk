from distutils.core import setup
from distutils.extension import Extension
from Cython.Build import cythonize

pyvdsk_extension = Extension(
    name="vdsk",
    sources=["vdsk.pyx"],
    libraries=["vdsk"],
)
setup(
    name="vdsk",
    ext_modules=cythonize([pyvdsk_extension])
)
