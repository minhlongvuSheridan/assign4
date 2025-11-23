using Microsoft.EntityFrameworkCore;
using TaskManagement.Core.Interfaces;
using TaskManagement.Core.Models;
using TaskManagement.Infrastructure.Data;
namespace TaskManagement.Infrastructure.Repositories;

public class TaskRepository : ITaskRepository
{
    private readonly ApplicationDbContext _context;
    public TaskRepository(ApplicationDbContext context)
    {
        _context = context;
    }
    public async Task<IEnumerable<TaskItem>> GetAllAsync()
    {
        return await _context.Tasks.ToListAsync();
    }
    public async Task<TaskItem?> GetByIdAsync(int id)
    {
        return await _context.Tasks.FindAsync(id);
    }
    public async Task<TaskItem> CreateAsync(TaskItem task)
    {
        task.CreatedAt = DateTime.UtcNow;
        _context.Tasks.Add(task);
        await _context.SaveChangesAsync();
        return task;
    }
    public async Task<TaskItem?> UpdateAsync(TaskItem task)
    {
        var existingTask = await _context.Tasks.FindAsync(task.Id);

        if (existingTask == null)
        {
            return null;
        }
        existingTask.Title = task.Title;
        existingTask.Description = task.Description;
        existingTask.Status = task.Status;
        existingTask.DueDate = task.DueDate;
        existingTask.UpdatedAt = DateTime.UtcNow;
        await _context.SaveChangesAsync();
        return existingTask;
    }
    public async Task<bool> DeleteAsync(int id)
    {
        var task = await _context.Tasks.FindAsync(id);
        if (task == null)
        {
            return false;
        }
        _context.Tasks.Remove(task);
        await _context.SaveChangesAsync();
        return true;
    }
    public async Task<bool> ExistsAsync(int id)
    {
        return await _context.Tasks.AnyAsync(t => t.Id == id);
    }
}