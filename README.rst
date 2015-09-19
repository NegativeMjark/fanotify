Fanotify - Monitoring Filesystem Events
=======================================

A simple C example of the fanotify_ system calls for linux.

.. _fanotify: http://man7.org/linux/man-pages/man7/fanotify.7.html

Building
--------

.. code:: bash

    make

Running
-------

To monitor all the close events on the root file-system run:

.. code:: bash

   sudo ./fanotify CLOSE MOUNT /
