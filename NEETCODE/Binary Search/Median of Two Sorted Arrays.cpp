/*
Số phần tử bên trái = số phần tử bên phải (hoặc lệch 1)
Max(trái) ≤ Min(phải)

*/
#include <vector>
#include <algorithm>
#include <climits>
using namespace std;
class Solution
{
public:
    double findMedianSortedArrays(vector<int> &nums1, vector<int> &nums2)
    {
        // đảm bảo nums1 là mảng nhỏ hơn
        if (nums1.size() > nums2.size())
            return findMedianSortedArrays(nums2, nums1);

        int m = nums1.size();
        int n = nums2.size();

        int l = 0, r = m;

        while (l <= r)
        {
            int i = (l + r) / 2;
            int j = (m + n + 1) / 2 - i;

            int A_left = (i == 0) ? INT_MIN : nums1[i - 1];
            int A_right = (i == m) ? INT_MAX : nums1[i];
            int B_left = (j == 0) ? INT_MIN : nums2[j - 1];
            int B_right = (j == n) ? INT_MAX : nums2[j];

            if (A_left <= B_right && B_left <= A_right)
            {
                // tìm được partition đúng
                if ((m + n) % 2 == 0)
                {
                    return (max(A_left, B_left) + min(A_right, B_right)) / 2.0;
                }
                else
                {
                    return max(A_left, B_left);
                }
            }
            else if (A_left > B_right)
            {
                r = i - 1;
            }
            else
            {
                l = i + 1;
            }
        }
        return 0.0; // never reach
    }
};

/*
Two pointers - O(m+n): Giống như Merge trong Merge Sort

double findMedianSortedArrays(vector<int>& a, vector<int>& b) {
    int m = a.size(), n = b.size();
    int i = 0, j = 0;
    int prev = 0, cur = 0;

    for (int k = 0; k <= (m + n) / 2; k++) {
        prev = cur;
        if (i < m && (j >= n || a[i] <= b[j])) {
            cur = a[i++];
        } else {
            cur = b[j++];
        }
    }

    if ((m + n) % 2 == 0)
        return (prev + cur) / 2.0;
    else
        return cur;
}
*/
