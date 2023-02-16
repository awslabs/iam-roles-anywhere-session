"""
  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

  Licensed under the Apache License, Version 2.0 (the "License").
  You may not use this file except in compliance with the License.
  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
"""
from pathlib import Path
from iam_rolesanywhere_session import __version__
from setuptools import setup

this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()


setup(
    name="iam_rolesanywhere_session",
    version=__version__,
    author="Thomas Buatois",
    author_email="tbuatois@amazon.fr",
    packages=["iam_rolesanywhere_session"],
    url="https://github.com/awslabs/iam-roles-anywhere-session",
    license="LICENSE",
    description="Boto3 session creator for IAM Roles Anywhere",
    long_description=long_description,
    long_description_content_type="text/markdown",
    python_requires=">=3.8",
    install_requires=[
        "pyOpenSSL>=22.0.0",
        "boto3>=1.24.55",
        "botocore>=1.27.55",
        "cryptography>=37.0.4",
    ],
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3",
    ],
)
