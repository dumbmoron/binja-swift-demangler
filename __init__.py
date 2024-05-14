import binaryninja
import subprocess

def run_demangler(symbols):
	return subprocess.check_output(["swift", "demangle", "--compact", "--simplified"], input="\n".join(symbols).encode()).decode().strip().split("\n")

def demangle_swift(bv):
	swift_functions = []
	results = run_demangler(map(lambda f: f.name, bv.functions))
	demangled_func_count = 0
	for (function, name) in zip(swift_functions, results):
		if name == function:
			continue

		demangled_func_count += 1
		if function.comment:
			function.comment = f"{function.comment} ({function.name})"
		else:
			function.comment = function.name
		function.name = name

	variables = bv.data_vars.values()
	results = run_demangler(map(lambda v: v.name, variables))
	demangled_var_count = 0

	for (variable, demangled_name) in zip(swift_variables, results):
		if variable.name != demangled_name:
			variable.name = demangled_name
			demangled_var_count += 1
			
	binaryninja.log_info(f"Swift demangling complete! Updated {len(demangled_func_count)} functions and {len(demangled_var_count)} variables.")

binaryninja.PluginCommand.register("Swift Demangler", "Demangles Swift", demangle_swift)
