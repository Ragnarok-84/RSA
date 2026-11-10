#include <stack>
#include <algorithm>
using namespace std;
class MinStack
{
private:
    stack<int> st;    // main stack
    stack<int> minSt; // stack to track minimums

public:
    MinStack() {}

    void push(int val)
    {
        st.push(val);
        if (minSt.empty())
            minSt.push(val);
        else
            minSt.push(min(val, minSt.top()));
    }

    void pop()
    {
        st.pop();
        minSt.pop();
    }

    int top()
    {
        return st.top();
    }

    int getMin()
    {
        return minSt.top();
    }
};
