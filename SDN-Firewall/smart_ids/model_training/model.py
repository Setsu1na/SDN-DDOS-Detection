"""
    author:
    date:21.6

"""
import torch
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
import torch.utils.data as Data
import time
import csv
import numpy as np
import matplotlib.pyplot as plt
import os


# 设置迭代次数
Epoch = 170
'''
基础配置：
------------------------------------------ No.1 ----------------------------------------------------        
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3)
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.conv4 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.lstm1 = nn.LSTM(input_size=11, hidden_size=48, num_layers=2, batch_first=True)
------------------------------------------ No.2 ----------------------------------------------------        
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3)
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.conv4 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.lstm1 = nn.LSTM(input_size=11, hidden_size=64, num_layers=2, batch_first=True)
------------------------------------------ No.3 ----------------------------------------------------        
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3)
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.conv4 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.lstm1 = nn.GRU(input_size=11, hidden_size=64, num_layers=2, batch_first=True)
------------------------------------------ No.4 ----------------------------------------------------  
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.gru1 = nn.GRU(input_size=11, hidden_size=48, num_layers=2, batch_first=True)

'''
batch_size = 200
np.random.seed(4396)
global acc_test


def load_data(root):
    feature = []
    label = []
    print('----------------------------------')
    # 用于测试集构建
    time_start = time.time()
    file_path = root
    with open(file_path, 'r', encoding='utf-8-sig') as data_from:
        # utf-8-sig 用于编码带BOM的csv文件
        csv_reader = csv.reader(data_from)
        next(csv_reader)
        for item in csv_reader:
            # print i
            print(item)
            tmp = list(map(float, item[1:25]))
            print(tmp)
            feature.append(tmp)
            label.append(int(item[25]))  # 添加标签（以独热向量表示）
    time_end = time.time()
    delta = time_end-time_start
    features = torch.tensor(feature)
    labels = torch.tensor(label, dtype=torch.long)


    dataset = torch.utils.data.TensorDataset(features, labels)
    data_iter = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True, drop_last=True, num_workers=4)
    print('数据读取总用时: %fs'%(delta))
    # print(feature[0],label[0],data_iter)
    # print(feature.shape)
    return features, labels, data_iter


def data_assign(feature, label):
    print('---------------------------------------')
    print('准备进行对读取数据的预处理：')
    feature_test = torch.tensor(feature, dtype=torch.float32)
    label_test = torch.tensor(label, dtype=torch.int64)
    return feature_test, label_test

def train2(model, train_iter, optimizer, criterion, epoch, Device, batch_size):
#def train(model, train_iter, optimizer, epoch, Device):
    acc = []
    model.train()
    count = 0
    correct = 0
    loss_sum = 0
#    correct1 = 0
#    for id, (data, target) in enumerate(zip(feature_train, label_train)):
    for id, (batch_features, batch_labels) in enumerate(train_iter):  # 乱序训练
        print(count)
        count += 1
        batch_features, batch_labels = batch_features.to(Device), batch_labels.to(Device)
        batch_features = batch_features.unsqueeze(dim=1)
        # print(batch_features.shape)
        optimizer.zero_grad()
        output = model(batch_features)  # torch.Size([1, 23])
        loss = criterion(output, batch_labels)
        # print()
        batch_labels = batch_labels.unsqueeze(dim=1) # 100 * 1
        loss_sum += loss
        loss.backward()
        optimizer.step()
        # print('step 1', F.log_softmax(output, dim=1))
        # print('step 2', F.log_softmax(output, dim=1).max(1, keepdim=True)[1], batch_labels) #  step 2 <class 'torch.return_types.max'>
        output1 = F.log_softmax(output, dim=1).max(1, keepdim=True)[1]  # torch.Size([1, 1]) 返回的是最大值的索引位置
        matrix = ( batch_labels == output1 )
        correct += matrix.sum()

#        correct += (1 if target.argmax(dim=1) == output.argmax(dim=1) else 0)
        if (id+1) % 100 == 0:
            print('Train Epoch: {},Loss: {:.6f}, Accuracy: {} / {} ({:.4f}%)'.format(
                epoch, loss_sum.item()/100. , correct, count * batch_size, 100. * correct / (count * batch_size)))
            acc.append(100. * correct / (count * batch_size))
            loss_sum = 0
    plt.plot(acc, c = 'red', label='pred')
    plt.ylabel('acc')
    plt.xlabel('number')
    plt.rcParams['figure.dpi'] = 300 # 设置图片分辨率为 1800*1200
    plt.rcParams['savefig.dpi'] = 300
    if not os.path.isdir(r'./pic3'):
        os.mkdir(r'./pic3')
    plt.savefig(r'./pic3/pic%s.png'%epoch)
    # plt.show()

    return np.sum(acc) / count

def test2(model, test_iter, criterion, epoch, Device, batch_size):
    global acc_test
    loss = 0
    model.eval()
    count = 0
    correct = 0
    #    for id, (data, target) in enumerate(zip(feature_train, label_train)):
    for id, (batch_features, batch_labels) in  enumerate(test_iter):  # 乱序训练
        count += 1
        batch_features, batch_labels = batch_features.to(Device), batch_labels.to(Device)
        batch_features = batch_features.unsqueeze(dim=1)
        output = model(batch_features)  # torch.Size([1, 23])
        loss += criterion(output, batch_labels).item()
        batch_labels = batch_labels.unsqueeze(dim=1)
        output = F.log_softmax(output, dim=1).max(1, keepdim=True)[1]  # torch.Size([1, 1])
        matrix = ( batch_labels == output )
        correct += matrix.sum()
        #correct += (1 if target.argmax(dim=1) == output.argmax(dim=1) else 0)
    print('Train Epoch: {},Loss: {:.6f}, Accuracy: {} / {} ({:.4f}%)'.format(
        epoch, loss/count, correct, count * batch_size, 100. * correct / (count * batch_size)))
    tmp_acc = 100. * correct / (count * batch_size)
    if acc_test < tmp_acc:
        try:
             state = {
                'net': model.state_dict(),
               'epoch': epoch,
               'name': 'LSTM',
                'acc_test':tmp_acc
            }

             if not os.path.isdir(r'./model'):
                os.mkdir(r'./model')
             torch.save(state, r'./model/dl-ids-multi.pth')
        except Exception as e:
          print("发生了错误：", e)
        else:
            print("保存成功！") # 72.5700%
        acc_test = tmp_acc

    return 100. * correct / (count * batch_size)

class ConvNet_multi(nn.Module):
    # 用于构建多分类模型
    def __init__(self):
        super(ConvNet_multi, self).__init__()
        # class torch.nn.Conv1d(in_channels, out_channels, kernel_size,
        # stride=1, padding=0, dilation=1, groups=1, bias=True)
        self.conv1 = nn.Conv1d(in_channels=1, out_channels=64, kernel_size=3)
        self.conv2 = nn.Conv1d(in_channels=64, out_channels=128, kernel_size=3)
        self.conv3 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.conv4 = nn.Conv1d(in_channels=128, out_channels=128, kernel_size=3)
        self.lstm1 = nn.LSTM(input_size=3, hidden_size=48, num_layers=2, batch_first=True) # 11/4
        self.gru1 = nn.GRU(input_size=11, hidden_size=48, num_layers=2, batch_first=True)
        # self.conv3 = nn.Conv1d(in_channels=128, out_channels=256, kernel_size=3)
        self.maxpool = nn.MaxPool1d(kernel_size=2, ceil_mode=True)
        self.avgpool = nn.AvgPool1d(kernel_size=2, ceil_mode=True)
        # 1 * 256 * x
        # self.fc1 = nn.Linear(6144, 1024) # with lstm
        self.fc1 = nn.Linear(3072, 128) # without lstm
        # self.fc2 = nn.Linear(1024, 2)
        # 用于多分类-8个类
        self.fc3 = nn.Linear(128, 64)
        # self.fc2 = nn.Linear(1024, 7) # with lstm
        self.fc2 = nn.Linear(64, 8) # without lstm
        self.softmax = nn.Softmax(dim=1)

    def forward(self, x):
        in_size = x.size(0)
        out = self.conv1(x)
        # out = F.gelu(out) # 1, 64, 39
# #        out = self.maxpool(out)# 1, 64, 20
#         out = self.conv2(out)
#         out = F.gelu(out)
#         out = self.maxpool(out)
#         out = self.conv3(out)
#         out = F.gelu(out)
#         out = self.conv4(out)
#         # print(out.size)
#         out_size = out.size
#         out = F.gelu(out)
        out = self.maxpool(out)
        # out, (h, c) = self.lstm1(out) # 1, 64, 70
        out, h = self.gru1(out)
        # Flatten()
        out = out.contiguous().view(in_size, -1)

        out = F.dropout(out, p=0.1)
        out = self.fc1(out)
        out = F.gelu(out)
        out = F.dropout(out, p=0.25)
        out = self.fc3(out)
        out = F.gelu(out)
        out = F.dropout(out, p=0.5)
        out = self.fc2(out)
        out = F.gelu(out)
        out = self.softmax(out)
        return out

if __name__ == '__main__':

    print("准备进行训练集读取：")
    feature_train, label_train, train_iter = load_data(root=r'train3.csv')
    print("准备进行测试集读取：")

    feature_test, label_test, test_iter = load_data(root=r'test3.csv')
    # 对训练集和测试集进行拷贝
    feature_train, label_train = data_assign(feature_train, label_train)
    feature_test, label_test = data_assign(feature_test, label_test)
    print(feature_train[0])

    # -------------------------------------------------------------------------------
    Device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    # model = ConvNet().to(Device)

    log_dir = './model/dl-ids-multi.pth'
    model = ConvNet_multi().to(Device)
    if os.path.exists(log_dir):
        checkpoint = torch.load(log_dir)
        model.load_state_dict(checkpoint['net'])
        start_epoch = checkpoint['epoch']
        acc_test = checkpoint['acc_test']
        print('加载 epoch {} 成功！'.format(start_epoch))
    else:
        start_epoch = 1
        acc_test = 0
        print('无保存模型，将从头开始训练！')


    # model = torch.load('./model/dl-ids-multi.pth')
    optimizer = optim.Adam(model.parameters(), lr=1e-5, weight_decay=1e-4)
    criterion = nn.CrossEntropyLoss()
    print('---------------------------------------')
    print('准备进行训练和测试：')
    test_acc = []
    train_acc = []
    for epoch in range(1, Epoch + 1):
        time_start = time.time()
        #        train(model, feature_train, label_train, train_iter, optimizer, criterion, epoch, Device)
        train_acc.append(train2(model, train_iter, optimizer, criterion, epoch, Device, batch_size))
        #        train(model, train_iter, optimizer, epoch, Device)
        time_end = time.time()
        #        test_acc.append(test2(model, feature_test, label_test, test_iter, criterion, epoch, Device))
        test_acc.append(test2(model, test_iter, criterion, epoch, Device, batch_size))
        delta = time_end - time_start
        print('训练一轮用时: %fs' % (delta))
        print('第{}轮迭代完成'.format(epoch))
    print("全部训练结束！")

    print("首先绘制测试集准确率图像")
    plt.plot(test_acc, c='red', label='pred')
    plt.ylabel('acc')
    plt.xlabel('number')
    plt.rcParams['figure.dpi'] = 300  # 设置图片分辨率为 1800*1200
    plt.rcParams['savefig.dpi'] = 300
    plt.savefig(r'./pic/pic-test-acc.png')
    plt.show()
    print("绘制训练集准确率图像")
    plt.plot(train_acc, c='red', label='pred')
    plt.ylabel('acc')
    plt.xlabel('number')
    plt.rcParams['figure.dpi'] = 300
    plt.rcParams['savefig.dpi'] = 300
    plt.savefig(r'./pic3/pic-train-acc.png')
    plt.show()


# if __name__ == '__main__':
#     blk = ConvNet_multi()
#     tmp = torch.randn(500, 1, 24)
#     out = blk(tmp)
#     print('block:', out.shape)
#     print('block:', out[0])
