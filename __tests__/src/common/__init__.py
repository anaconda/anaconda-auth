# TEST_HOME_DIR refers to the top level directory of the "test" package
import os

TEST_HOME_DIR = os.path.dirname(os.path.abspath(__file__))

# TEST_DATA_DIR is used as a target download location for remote resources
TEST_DATA_DIR = os.path.join(TEST_HOME_DIR, "data")
