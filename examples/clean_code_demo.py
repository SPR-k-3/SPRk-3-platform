"""
Example of clean code that passes SPR{K}3 analysis
"""

# Normal configuration
learning_rate = 0.001
batch_size = 32
epochs = 10

def process_data(input_data):
    """Standard data processing"""
    return input_data.strip().lower()

def save_results(data):
    """Save to local file"""
    with open("results.json", "w") as f:
        json.dump(data, f)

print("This code should pass with no threats detected")
