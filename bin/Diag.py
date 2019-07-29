import logging
import os


# Use the **args pattern to ignore options we don't care about.
def setup(parser=None, callback=None, **kwargs):
    logging.debug("setup() was called!")

    # Declare that we're going to use REST later
    callback.will_need_rest()


# The options are out of order, as is possible for keyword invocation
def collect_diag_info(diag, options=None, global_options=None, app_dir=None, **kwargs):
    app = app_dir.split(os.path.sep)[-1]
    logging.info("collect_diag_info() was called for app {}".format(app))

    # Collect a directory from the app
    a_dir = os.path.join(app_dir, 'bin')
    logging.info("collecting bin: {}".format(a_dir))
    diag.add_dir(a_dir, 'bin')

    # Collect a directory from the app
    a_dir = os.path.join(app_dir, 'appserver')
    logging.info("collecting appserver: {}".format(a_dir))
    diag.add_dir(a_dir, 'appserver')

    # Collect a directory from the app
    a_dir = os.path.join(app_dir, 'local')
    logging.info("collecting local: {}".format(a_dir))
    diag.add_dir(a_dir, 'local')

    a_dir = os.path.join(app_dir, '..', '..', '..', 'var', 'log', 'splunk', app)
    logging.info("collecting app logs: {}".format(a_dir))
    diag.add_dir(a_dir, "application_logs")

    # Collect some REST endpoint data
    diag.add_rest_endpoint("/services/server/info", "server_info.xml")