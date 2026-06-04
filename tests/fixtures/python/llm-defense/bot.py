"""Example file with LLM defense issues for testing."""
import openai


def ask_llm(user_input):
    prompt = f"Summarize the following: {user_input}"
    response = client.chat.completions.create(
        messages=[{"role": "user", "content": prompt}]
    )
    return response


def run_agent():
    while True:
        response = agent.step()
        if response.done:
            return response


def execute_query(user_query):
    result = client.chat.completions.create(
        messages=[{"role": "user", "content": user_query}]
    )
    cursor.execute(f"SELECT * FROM {result}")
