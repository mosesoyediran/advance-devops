import os


class K8sContextManager:
    def load_k8s_contexts(self):
        command = "kubectl config get-contexts -o=name"
        return os.popen(command).read().splitlines()

    def get_current_context(self):
        command = "kubectl config current-context"
        return os.popen(command).read().strip()

    def switch_k8s_context(self, context):
        command = f"kubectl config use-context {context}"
        return os.popen(command).read().strip()
