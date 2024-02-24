Install Guide
=============

Being a modern Python framework, pyroblock requires an up to date version of Python to be installed in your system.
We recommend using the latest versions of both Python 3 and pip.

.. contents:: Contents
    :backlinks: none
    :depth: 1
    :local:

-----

Install pyroblack
----------------

-   The easiest way to install and upgrade pyroblack to its latest stable version:

    .. code-block:: text

        $ pip3 install -U pyroblack

-   or, with :doc:`TgCrypto <../topics/speedups>` as extra requirement (recommended):

    .. code-block:: text

        $ pip3 install -U pyroblack tgcrypto

Verifying
---------

To verify that pyroblack is correctly installed, open a Python shell and import it.
If no error shows up you are good to go.

.. parsed-literal::

    >>> import pyrogram
    >>> pyrogram.__version__
    'x.y.z'

.. _`Github repo`: http://github.com/eyMarv/pyroblack
