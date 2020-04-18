class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable
  has_many :posts
  mount_uploader :avatar, ImageUploader
  validates :nickname,  length: { maximum: 15 }, uniqueness: true, presence: true
  validates :email,  length: { maximum: 30 }, uniqueness: true
  validates :avatar, presence: true
end
