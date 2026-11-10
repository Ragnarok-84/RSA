#include <vector>
#include <string>
#include <stack>
using namespace std;
class Solution
{
public:
    int evalRPN(vector<string> &tokens)
    {
        stack<int> st;

        for (string s : tokens)
        {
            if (s == "+" || s == "-" || s == "*" || s == "/")
            {
                int a = st.top();
                st.pop();
                int b = st.top();
                st.pop();

                if (s == "+")
                    st.push(b + a);
                else if (s == "-")
                    st.push(b - a);
                else if (s == "*")
                    st.push(b * a);
                else
                    st.push(b / a); // truncates toward zero
            }
            else
            {
                st.push(stoi(s)); // stoi xử lý được số âm
            }
        }

        return st.top();
    }
};
