# AWS Incident Response Automations

## Overview
This repository offers a collection of automations designed to speed up incident response in AWS environments. Each automation is stored in its own folder, complete with all necessary code and a README explaining how it works and how to set it up.

## Features
**Folders for each automation:** Every automation has its own folder with code, Terraform code, and detailed guides.
**Easy to deploy:** Use Terraform to deploy automations easily, ensuring the automations have all necesary permissions and resources.
**Optional Datadog workflows:** Enhance automation by integrating it into Datadog Workflows, allowing Datadog users to trigger the automations without accessing AWS.

## How to Use
**Clone the Repo:** Download the repository and choose the automation you need.
**Setup:** Adjust the Terraform configurations to match your AWS environment.
**Deploy:** Apply the setup using Terraform.
**Datadog Integration (Optional):** Datadog users can import the provided JSON to their workflows (and add additional configurations if you wish).
**Test:** Simulate an incident and make sure the deployed automation fits what you are expecting. Make the necessary changes to adapt the automation to your environment.
