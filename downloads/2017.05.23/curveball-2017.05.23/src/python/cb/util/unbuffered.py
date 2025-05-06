# Derived from a post by Magnus Lycka on the Tutor mailing list at python.org.
# Postings on this mailing list are licensed under the Creative Commons License,
# v3.0.

"""
Provide a simple way to "unbuffer" a stream
"""

import sys

class Unbuffered(object):
    """
    A simple wrapper class to create unbuffered streams
    from (potentially) buffered streams
    """

    def __init__(self, stream):
        self.stream = stream

    def write(self, data):
        self.stream.write(data)
        self.stream.flush()

    def __getattr__(self, attr):
        return getattr(self.stream, attr)

# To make integration simpler for programs that redirect the output of
# Python scripts to files, and then scan those files to see if certain
# output has appeared, we provide a convenience function to make stdout
# and stderr unbuffered.
#
def unbuffer():
    """
    Wrap stdout and stderr in Unbuffered instances
    """

    sys.stdout = Unbuffered(sys.stdout)
    sys.stderr = Unbuffered(sys.stderr)

    return
