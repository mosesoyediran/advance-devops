from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QButtonGroup, QCheckBox, QComboBox, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QRadioButton,
                             QTextEdit, QVBoxLayout, QWidget)


class GitLabWorkflowConfigurator(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        # Create main layout as a horizontal layout with 2 columns
        main_layout = QHBoxLayout()

        # Left column for input
        input_layout = QVBoxLayout()

        # Stages input
        self.stages_checkbox = QCheckBox("Configure Stages")
        self.stages_checkbox.stateChanged.connect(self.toggle_stages)
        input_layout.addWidget(self.stages_checkbox)

        self.stages_input = QLineEdit()
        self.stages_input.setPlaceholderText("Enter stages (comma separated)")
        input_layout.addWidget(self.stages_input)
        self.stages_input.setVisible(False)

        # Variables input
        self.variables_checkbox = QCheckBox("Configure Variables")
        self.variables_checkbox.stateChanged.connect(self.toggle_variables)
        input_layout.addWidget(self.variables_checkbox)

        # Scroll area to handle many variables
        self.variables_area = QWidget()
        self.variables_layout = QVBoxLayout()
        self.variables_area.setLayout(self.variables_layout)

        self.add_variable_button = QPushButton("Add Variable")
        self.add_variable_button.clicked.connect(self.add_variable_input)
        input_layout.addWidget(self.add_variable_button)
        input_layout.addWidget(self.variables_area)
        self.variables_area.setVisible(False)

        # Jobs input with radio button and form elements
        self.jobs_checkbox = QCheckBox("Configure Jobs")
        self.jobs_checkbox.stateChanged.connect(self.toggle_jobs)
        input_layout.addWidget(self.jobs_checkbox)

        # Scroll area to handle multiple jobs
        self.jobs_area = QWidget()
        self.jobs_layout = QVBoxLayout()
        self.jobs_area.setLayout(self.jobs_layout)

        self.add_job_button = QPushButton("Add Job")
        self.add_job_button.clicked.connect(self.add_job_input)
        input_layout.addWidget(self.add_job_button)
        input_layout.addWidget(self.jobs_area)
        self.jobs_area.setVisible(False)

        # Add to the left column
        main_layout.addLayout(input_layout)

        # Right column for output and preview
        output_layout = QVBoxLayout()

        # Preview button and output area
        self.preview_button = QPushButton("Preview .gitlab-ci.yml")
        self.preview_button.clicked.connect(self.preview_pipeline)
        output_layout.addWidget(self.preview_button)

        self.output_preview = QTextEdit()
        self.output_preview.setReadOnly(True)  # Output should be read-only
        output_layout.addWidget(self.output_preview)

        # Add to the right column
        main_layout.addLayout(output_layout)

        # Set the main layout
        self.setLayout(main_layout)

    def toggle_stages(self, state):
        """Show/hide stages input based on checkbox state."""
        self.stages_input.setVisible(state == Qt.Checked)

    def toggle_variables(self, state):
        """Show/hide variables area based on checkbox state."""
        self.variables_area.setVisible(state == Qt.Checked)

    def toggle_jobs(self, state):
        """Show/hide jobs area based on checkbox state."""
        self.jobs_area.setVisible(state == Qt.Checked)

    def add_variable_input(self):
        """Add a new input field for variables."""
        variable_input = QLineEdit()
        variable_input.setPlaceholderText("Enter variable (e.g., IMAGE_NAME=$CI_REGISTRY_IMAGE)")
        self.variables_layout.addWidget(variable_input)

    def add_job_input(self):
        """Add a new input area for job configuration with a radio button for more options."""
        job_input = QWidget()
        job_layout = QVBoxLayout()

        # Radio button group for showing/hiding advanced job details
        job_radio_group = QButtonGroup(job_input)
        job_radio_button = QRadioButton("Configure Job")
        job_radio_button.toggled.connect(lambda checked, job_layout=job_layout: self.toggle_job_details(checked, job_layout))
        job_radio_group.addButton(job_radio_button)

        # Job Name
        job_name_input = QLineEdit()
        job_name_input.setPlaceholderText("Enter job name")
        job_layout.addWidget(job_radio_button)
        job_layout.addWidget(job_name_input)

        # Advanced Job Details (initially hidden)
        advanced_job_area = QWidget()
        advanced_job_layout = QVBoxLayout()

        # Job details (e.g., image, stage, cache, before_script, etc.)
        job_image_input = QLineEdit()
        job_image_input.setPlaceholderText("Enter image")
        advanced_job_layout.addWidget(job_image_input)

        job_stage_input = QLineEdit()
        job_stage_input.setPlaceholderText("Enter stage")
        advanced_job_layout.addWidget(job_stage_input)

        job_cache_input = QLineEdit()
        job_cache_input.setPlaceholderText("Enter cache key")
        advanced_job_layout.addWidget(job_cache_input)

        job_tags_input = QLineEdit()
        job_tags_input.setPlaceholderText("Enter tags (comma separated)")
        advanced_job_layout.addWidget(job_tags_input)

        job_before_script_input = QLineEdit()
        job_before_script_input.setPlaceholderText("Enter before_script commands")
        advanced_job_layout.addWidget(job_before_script_input)

        job_script_input = QLineEdit()
        job_script_input.setPlaceholderText("Enter script")
        advanced_job_layout.addWidget(job_script_input)

        job_artifacts_paths_input = QLineEdit()
        job_artifacts_paths_input.setPlaceholderText("Enter artifacts paths")
        advanced_job_layout.addWidget(job_artifacts_paths_input)

        job_artifacts_when_input = QLineEdit()
        job_artifacts_when_input.setPlaceholderText("Enter artifacts when")
        advanced_job_layout.addWidget(job_artifacts_when_input)

        job_reports_junit_input = QLineEdit()
        job_reports_junit_input.setPlaceholderText("Enter reports junit file")
        advanced_job_layout.addWidget(job_reports_junit_input)

        job_environment_input = QLineEdit()
        job_environment_input.setPlaceholderText("Enter environment name")
        advanced_job_layout.addWidget(job_environment_input)

        job_run_functional_tests_input = QLineEdit()
        job_run_functional_tests_input.setPlaceholderText("Enter run functional tests script")
        advanced_job_layout.addWidget(job_run_functional_tests_input)

        job_deploy_to_staging_input = QLineEdit()
        job_deploy_to_staging_input.setPlaceholderText("Enter deploy to staging script")
        advanced_job_layout.addWidget(job_deploy_to_staging_input)

        job_needs_input = QLineEdit()
        job_needs_input.setPlaceholderText("Enter job needs")
        advanced_job_layout.addWidget(job_needs_input)

        job_extends_input = QLineEdit()
        job_extends_input.setPlaceholderText("Enter extends (e.g., .deploy)")
        advanced_job_layout.addWidget(job_extends_input)

        job_app_port_input = QLineEdit()
        job_app_port_input.setPlaceholderText("Enter APP_PORT")
        advanced_job_layout.addWidget(job_app_port_input)

        # Add the advanced job layout to the advanced job area
        advanced_job_area.setLayout(advanced_job_layout)
        advanced_job_area.setVisible(False)  # Initially hidden

        job_layout.addWidget(advanced_job_area)

        # Add the job layout to the main job area
        self.jobs_layout.addWidget(job_input)

        # Attach the job layout to the job input widget
        job_input.setLayout(job_layout)

    def toggle_job_details(self, checked, job_layout):
        """Show or hide the advanced job details based on the radio button."""
        for i in range(job_layout.count()):
            widget = job_layout.itemAt(i).widget()
            if isinstance(widget, QWidget) and widget != job_layout.itemAt(0).widget():  # Skip the radio button
                widget.setVisible(checked)

    def preview_pipeline(self):
        """Generate the pipeline YAML and display it in the output preview."""
        stages = self.stages_input.text().split(',') if self.stages_checkbox.isChecked() else []
        variables = []
        jobs = []

        # Collect variables
        for i in range(self.variables_layout.count()):
            variable_input = self.variables_layout.itemAt(i).widget()
            if isinstance(variable_input, QLineEdit):
                variable = variable_input.text()
                if variable:
                    variables.append(variable)

        # Collect jobs
        for i in range(self.jobs_layout.count()):
            job_input_widget = self.jobs_layout.itemAt(i).widget()
            if isinstance(job_input_widget, QWidget):
                job_name_input = job_input_widget.layout().itemAt(1).widget()  # Job name
                advanced_job_widget = job_input_widget.layout().itemAt(2).widget()  # Advanced job details
                job_image_input = advanced_job_widget.layout().itemAt(0).widget()  # Image
                job_stage_input = advanced_job_widget.layout().itemAt(1).widget()  # Stage
                job_script_input = advanced_job_widget.layout().itemAt(4).widget()  # Script

                job = {
                    'name': job_name_input.text(),
                    'image': job_image_input.text(),
                    'stage': job_stage_input.text(),
                    'script': job_script_input.text()
                }
                jobs.append(job)

        # Generate .gitlab-ci.yml content
        yml_content = self.generate_gitlab_ci_yml(stages, variables, jobs)
        self.output_preview.setText(yml_content)

    def generate_gitlab_ci_yml(self, stages, variables, jobs):
        """Generate .gitlab-ci.yml content based on the user inputs."""
        yml_content = ""

        if stages:
            yml_content += "stages:\n"
            for stage in stages:
                yml_content += f"  - {stage.strip()}\n"

        if variables:
            yml_content += "\nvariables:\n"
            for variable in variables:
                yml_content += f"  {variable}\n"

        if jobs:
            for job in jobs:
                yml_content += f"\n{job['name']}:\n"
                yml_content += f"  image: {job['image']}\n"
                yml_content += f"  stage: {job['stage']}\n"
                yml_content += f"  script:\n"
                yml_content += f"    - {job['script']}\n"

        return yml_content
